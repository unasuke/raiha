# frozen_string_literal: true

require_relative "error"

module Raiha::Next::HTTP3::QPACK
  # Reads the primitives of RFC 9204 "Primitives" from `bytes` between
  # `offset` and `limit` without copying them first. A field past the limit
  # raises Truncated.
  class Reader
    # RFC 9204 "Prefixed Integers": up to 62 bits must decode.
    MAX_INTEGER = (1 << 62) - 1
    # Continuation bytes enough for MAX_INTEGER after any prefix (7 × 9 = 63
    # bits); an encoding longer than that is refused before its value is.
    MAX_CONTINUATIONS = 9

    attr_reader :offset

    def initialize(bytes, offset = 0, limit = bytes.bytesize)
      @bytes = bytes
      @offset = offset
      @limit = limit
    end

    def eof? = @offset >= @limit

    # RFC 7541 "Integer Representation" with a `prefix`-bit prefix. The bits
    # of the first byte above the prefix belong to the caller, which has
    # read them already.
    def integer(prefix)
      mask = (1 << prefix) - 1
      value = u8 & mask
      return value if value < mask
      MAX_CONTINUATIONS.times do |index|
        byte = u8
        value += (byte & 0x7f) << (7 * index)
        next if byte >= 0x80
        raise IntegerOverflow, "an integer above 2^62 - 1" if value > MAX_INTEGER
        return value
      end
      raise IntegerOverflow, "an integer of more than #{MAX_CONTINUATIONS} continuation bytes"
    end

    private def u8
      raise Truncated, "a byte wanted, none left" if eof?
      byte = @bytes.getbyte(@offset) #: Integer
      @offset += 1
      byte
    end
  end
end
