# frozen_string_literal: true

require_relative "../error_code"

module Raiha::Next::QUIC
  # The encoding of QUIC packets and frames: values in, bytes out, and back.
  # Module functions over Reader and Writer; nothing here holds state.
  module Wire
    # Bytes from the peer that do not decode. `code` is the transport error
    # to close the connection with, when the bytes came in a frame; a packet
    # that does not decode is dropped instead.
    class Malformed < StandardError
      attr_reader :code

      def initialize(message = nil, code: ErrorCode::FRAME_ENCODING_ERROR)
        super(message)
        @code = code
      end
    end

    # The bytes ran out before a field did.
    class Truncated < Malformed; end

    # RFC 9000 "Variable-Length Integer Encoding": the two high bits of the
    # first byte give the length, 1, 2, 4 or 8 bytes.
    module Varint
      MAX = (1 << 62) - 1

      def self.size(value)
        raise ArgumentError, "a varint is 0..2^62-1, not #{value.inspect}" unless value.is_a?(Integer) && value.between?(0, MAX)
        if value < (1 << 6) then 1
        elsif value < (1 << 14) then 2
        elsif value < (1 << 30) then 4
        else 8
        end
      end

      # The shortest encoding of `value`.
      def self.encode(value)
        case size(value)
        when 1 then [value].pack("C")
        when 2 then [0x4000 | value].pack("n")
        when 4 then [0x8000_0000 | value].pack("N")
        else [0xc000_0000_0000_0000 | value].pack("Q>")
        end
      end
    end

    # Reads fields from `bytes` between `offset` and `limit` without copying
    # them first. A field past the limit raises Truncated.
    class Reader
      attr_reader :offset

      def initialize(bytes, offset = 0, limit = bytes.bytesize)
        @bytes = bytes
        @offset = offset
        @limit = limit
      end

      def remaining = @limit - @offset

      def eof? = @offset >= @limit

      def u8 = take(1).getbyte(0).to_i

      def u16 = take(2).unpack1("n").to_i

      def u32 = take(4).unpack1("N").to_i

      # The value and how many bytes it took, for the checks of a shortest
      # encoding (frame types must use one).
      def varint_with_size
        first = @bytes.getbyte(@offset) or raise Truncated, "a varint is cut short"
        size = 1 << (first >> 6)
        raw = take(size)
        value = case size
          when 1 then first
          when 2 then raw.unpack1("n").to_i & 0x3fff
          when 4 then raw.unpack1("N").to_i & 0x3fff_ffff
          else raw.unpack1("Q>").to_i & Varint::MAX
          end
        [value, size]
      end

      def varint = varint_with_size.first

      def bytes(length) = take(length)

      # The rest, up to the limit.
      def rest = take(remaining)

      # A Reader over the next `length` bytes, which this one skips.
      def sub(length)
        raise Truncated, "#{length} bytes wanted, #{remaining} left" if length > remaining
        reader = Reader.new(@bytes, @offset, @offset + length)
        @offset += length
        reader
      end

      private def take(length)
        raise Truncated, "#{length} bytes wanted, #{remaining} left" if length > remaining
        value = @bytes.byteslice(@offset, length).to_s
        @offset += length
        value
      end
    end

    class Writer
      def initialize
        @buffer = String.new(encoding: Encoding::BINARY)
      end

      def u8(value) = tap { @buffer << [value].pack("C") }

      def u16(value) = tap { @buffer << [value].pack("n") }

      def u32(value) = tap { @buffer << [value].pack("N") }

      def varint(value) = tap { @buffer << Varint.encode(value) }

      def bytes(value) = tap { @buffer << value.b }

      def bytesize = @buffer.bytesize

      def to_s = @buffer
    end
  end
end
