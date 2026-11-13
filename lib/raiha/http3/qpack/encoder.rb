# frozen_string_literal: true

require_relative "field"
require_relative "result"
require_relative "static_table"
require_relative "reader"
require_relative "writer"

module Raiha::Next::HTTP3::QPACK
  # The encoder of one connection. It refers to the static table and sends
  # the rest as literals: it inserts nothing into the dynamic table, so a
  # field section never waits on the encoder stream and no entry is held
  # by a reference the decoder has yet to acknowledge.
  class Encoder
    # The representations of RFC 9204 "Field Line Representations", as the
    # bits above their prefixes.
    INDEXED_STATIC = 0b1100_0000 # Indexed Field Line, T = 1
    NAME_REFERENCE_STATIC = 0b0101_0000 # Literal Field Line with Name Reference, T = 1
    NAME_REFERENCE_NEVER_INDEXED = 0b0010_0000
    LITERAL_NAME = 0b0010_0000 # Literal Field Line with Literal Name
    LITERAL_NAME_NEVER_INDEXED = 0b0001_0000

    def initialize
      # The decoder stream's bytes of an instruction yet to arrive whole: at
      # most an integer's ten bytes, as a longer one fails to decode.
      @pending = String.new(encoding: Encoding::BINARY)
      @failure = nil
    end

    # The field section of `fields` for the stream `stream_id`. Its
    # Required Insert Count and Base are both 0. A field in the static
    # table goes as its index, one whose name is there as a reference to
    # the name, and the rest as literals; a never-indexed one is always a
    # literal.
    def encode(stream_id, fields)
      writer = Writer.new.integer(0, 8).integer(0, 7)
      fields.each { |field| represent(writer, field) }
      writer.to_s
    end

    # Follows the instructions in `bytes` from the decoder stream (RFC 9204
    # "Decoder Instructions"), keeping an instruction cut short for the
    # bytes after it. With no section that refers to the dynamic table, a
    # Section Acknowledgment has nothing to acknowledge and an Insert Count
    # Increment nothing to count, so either is a Failure, as is anything
    # after one; a Stream Cancellation has nothing to cancel.
    def receive_decoder_stream(bytes)
      return @failure if @failure
      @pending.append_as_bytes(bytes)
      reader = Reader.new(@pending)
      until reader.eof?
        start = reader.offset
        begin
          follow(reader)
        rescue Truncated
          @pending = @pending.byteslice(start..) #: String
          return
        end
      end
      @pending = String.new(encoding: Encoding::BINARY)
      nil
    rescue Malformed => error
      @failure = Failure.new(code: ErrorCode::DECODER_STREAM_ERROR, reason: error.message)
    end

    # The bytes to write on the encoder stream: none, with nothing inserted
    # into the dynamic table.
    def take_instructions = String.new(encoding: Encoding::BINARY)

    private def follow(reader)
      first = reader.peek
      if first >= 0b1000_0000
        stream_id = reader.integer(7)
        raise Malformed, "a Section Acknowledgment for stream #{stream_id}, which has no section to acknowledge"
      elsif first >= 0b0100_0000
        reader.integer(6)
      else
        increment = reader.integer(6)
        raise Malformed, "an Insert Count Increment of #{increment}, with no entry inserted"
      end
    end

    private def represent(writer, field)
      never_indexed = field.never_indexed
      if !never_indexed && (index = StaticTable.find(field.name, field.value))
        writer.integer(index, 6, INDEXED_STATIC)
      elsif (index = StaticTable.find_name(field.name))
        writer.integer(index, 4, NAME_REFERENCE_STATIC | (never_indexed ? NAME_REFERENCE_NEVER_INDEXED : 0)).string(field.value, 8)
      else
        writer.string(field.name, 4, LITERAL_NAME | (never_indexed ? LITERAL_NAME_NEVER_INDEXED : 0)).string(field.value, 8)
      end
    end
  end
end
