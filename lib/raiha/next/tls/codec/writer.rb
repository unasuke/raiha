# frozen_string_literal: true

require_relative "error"

module Raiha::Next::TLS::Codec
  # An append-only BINARY buffer. `#vector` writes a zero length prefix,
  # yields, and then fills the prefix in with `setbyte`, so nested vectors are
  # written in one pass without allocating a String per length.
  #
  # The buffer is always BINARY: `String#<<` with an Integer appends a code
  # point, which is one byte only in a BINARY string.
  class Writer
    PAD = ["".b, "\0".b, "\0\0".b, "\0\0\0".b].freeze #: Array[String]

    def initialize
      @buf = String.new(encoding: Encoding::BINARY)
    end

    def u8(v)
      check_range(v, 0xff)
      @buf << v
      nil
    end

    def u16(v)
      check_range(v, 0xffff)
      @buf << (v >> 8) << (v & 0xff)
      nil
    end

    def u24(v)
      check_range(v, 0xffffff)
      @buf << (v >> 16) << ((v >> 8) & 0xff) << (v & 0xff)
      nil
    end

    def u32(v)
      check_range(v, 0xffffffff)
      @buf << (v >> 24) << ((v >> 16) & 0xff) << ((v >> 8) & 0xff) << (v & 0xff)
      nil
    end

    def bytes(s)
      @buf << (s.encoding == Encoding::BINARY ? s : s.b)
      nil
    end

    # Writes a `len_bytes`-byte length prefix followed by whatever the block
    # writes. The length is filled in after the block returns. `min:` and
    # `max:` are the bounds from the vector's definition, the same ones
    # `Reader#vector` checks, so nothing written here fails to parse for its
    # length.
    def vector(len_bytes, min: 0, max: nil)
      pad = PAD[len_bytes] or raise ArgumentError, "length prefix must be 1 to 3 bytes: #{len_bytes}"
      pos = @buf.bytesize
      @buf << pad
      yield
      len = @buf.bytesize - pos - len_bytes
      raise EncodeError, "vector too long: #{len} bytes" if len >= (1 << (8 * len_bytes))
      raise EncodeError, "vector length #{len} is out of range #{min}..#{max}" if len < min || (max && len > max)
      case len_bytes
      when 1
        @buf.setbyte(pos, len)
      when 2
        @buf.setbyte(pos, len >> 8)
        @buf.setbyte(pos + 1, len & 0xff)
      else
        @buf.setbyte(pos, len >> 16)
        @buf.setbyte(pos + 1, (len >> 8) & 0xff)
        @buf.setbyte(pos + 2, len & 0xff)
      end
      nil
    end

    def to_s = @buf

    private def check_range(v, max)
      raise EncodeError, "#{v} is out of range 0..#{max}" unless 0 <= v && v <= max
    end
  end
end
