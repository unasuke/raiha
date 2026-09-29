# frozen_string_literal: true

require_relative "error"

module Raiha::Next::TLS::Codec
  # A cursor over a byte string. `#vector` hands its block a view that shares
  # the buffer and only narrows `(pos, limit)`, and checks that the block
  # consumed the whole vector. Integers are read with `getbyte`, which YJIT and
  # ZJIT compile far better than `unpack1(offset:)`.
  class Reader
    def initialize(buf, pos = 0, limit = buf.bytesize)
      @buf = buf
      @pos = pos
      @limit = limit
    end

    def u8
      i = @pos
      raise Truncated if i + 1 > @limit
      @pos = i + 1
      @buf.getbyte(i) #: Integer
    end

    # The bounds check above guarantees that every `getbyte` below is in range.
    def u16
      i = @pos
      raise Truncated if i + 2 > @limit
      b = @buf
      @pos = i + 2
      (b.getbyte(i) << 8) | b.getbyte(i + 1) # steep:ignore
    end

    def u24
      i = @pos
      raise Truncated if i + 3 > @limit
      b = @buf
      @pos = i + 3
      (b.getbyte(i) << 16) | (b.getbyte(i + 1) << 8) | b.getbyte(i + 2) # steep:ignore
    end

    def u32
      i = @pos
      raise Truncated if i + 4 > @limit
      b = @buf
      @pos = i + 4
      (b.getbyte(i) << 24) | (b.getbyte(i + 1) << 16) | (b.getbyte(i + 2) << 8) | b.getbyte(i + 3) # steep:ignore
    end

    # A frozen BINARY copy of the next `n` bytes.
    def bytes(n)
      i = @pos
      raise Truncated if i + n > @limit
      @pos = i + n
      @buf.byteslice(i, n).force_encoding(Encoding::BINARY).freeze # steep:ignore
    end

    # `opaque field<min..max>` with a `len_bytes`-byte length prefix.
    def opaque(len_bytes, max:, min: 0)
      bytes(read_length(len_bytes, min, max))
    end

    # Yields a view over the vector's contents and raises TrailingData if the
    # block leaves any of it unread.
    def vector(len_bytes, max:, min: 0)
      len = read_length(len_bytes, min, max)
      i = @pos
      raise Truncated if i + len > @limit
      sub = Reader.new(@buf, i, i + len)
      yield sub
      sub.finish!
      @pos = i + len
      nil
    end

    def eof? = @pos >= @limit

    def remaining = @limit - @pos

    def finish!
      raise TrailingData unless @pos == @limit
    end

    private def read_length(len_bytes, min, max)
      len =
        case len_bytes
        when 1 then u8
        when 2 then u16
        when 3 then u24
        else raise ArgumentError, "length prefix must be 1 to 3 bytes: #{len_bytes}"
        end
      raise RangeViolation unless min <= len && len <= max
      len
    end
  end
end
