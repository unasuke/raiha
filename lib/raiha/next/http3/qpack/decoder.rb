# frozen_string_literal: true

require_relative "dynamic_table"
require_relative "error_code"
require_relative "reader"
require_relative "result"
require_relative "static_table"

module Raiha::Next::HTTP3::QPACK
  # The decoder of one connection: it follows the encoder stream into its
  # dynamic table and decodes field sections against it. What the peer
  # sends never raises; it comes back as a Failure.
  class Decoder
    DEFAULT_MAX_FIELD_SECTION_SIZE = 65_536

    # `max_table_capacity` and `max_blocked_streams` are what this end
    # sends as SETTINGS_QPACK_MAX_TABLE_CAPACITY and
    # SETTINGS_QPACK_BLOCKED_STREAMS; both default to 0, as in RFC 9204
    # "Configuration".
    def initialize(max_table_capacity: 0, max_blocked_streams: 0, max_field_section_size: DEFAULT_MAX_FIELD_SECTION_SIZE)
      @table = DynamicTable.new(max_table_capacity)
      @max_blocked_streams = max_blocked_streams
      @max_field_section_size = max_field_section_size
      # The encoder stream's bytes of an instruction yet to arrive whole, and
      # how many of them it needs at least before it is worth reading again.
      @pending = String.new(encoding: Encoding::BINARY)
      @needed = 0
      @failure = nil
    end

    # Follows the instructions in `bytes` from the encoder stream (RFC 9204
    # "Encoder Instructions"), keeping an instruction cut short for the
    # bytes after it. A string that would not fit the dynamic table is
    # refused as soon as its length shows it, before its bytes come.
    def receive_encoder_stream(bytes)
      return @failure if @failure # steep:ignore
      @pending.append_as_bytes(bytes)
      return [] if @pending.bytesize < @needed
      reader = Reader.new(@pending)
      until reader.eof?
        start = reader.offset
        begin
          follow(reader)
        rescue Truncated => truncated
          if start.positive?
            @pending = @pending.byteslice(start..) #: String
          end
          @needed = truncated.needed - start
          return []
        end
      end
      @pending = String.new(encoding: Encoding::BINARY)
      @needed = 0
      []
    rescue Malformed, TooLong => error
      @failure = Failure.new(code: ErrorCode::ENCODER_STREAM_ERROR, reason: error.message)
    end

    private def follow(reader)
      first = reader.peek
      if first >= 0b1000_0000 # Insert with Name Reference
        static = first[6] == 1
        name = static ? static_name(reader.integer(6)) : relative_entry(reader.integer(6)).first
        @table.insert(name, reader.string(8, room - name.bytesize))
      elsif first >= 0b0100_0000 # Insert with Literal Name
        name = reader.string(6, room)
        @table.insert(name, reader.string(8, room - name.bytesize))
      elsif first >= 0b0010_0000 # Set Dynamic Table Capacity
        @table.resize(reader.integer(5))
      else # Duplicate
        name, value = relative_entry(reader.integer(5))
        @table.insert(name, value)
      end
    end

    # The octets of name and value an entry may have and still fit.
    private def room = @table.capacity - DynamicTable::ENTRY_OVERHEAD

    private def static_name(index)
      entry = StaticTable.entry(index) or raise Malformed, "no static entry #{index}"
      entry.first
    end

    # RFC 9204 "Relative Indexing": on the encoder stream, 0 is the entry
    # inserted last.
    private def relative_entry(index)
      absolute = @table.insert_count - 1 - index
      @table.entry(absolute) or raise Malformed, "no dynamic entry at relative index #{index}"
    end
  end
end
