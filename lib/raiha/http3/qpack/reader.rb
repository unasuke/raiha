# frozen_string_literal: true

require_relative "error"
require_relative "huffman"

module Raiha::HTTP3::QPACK
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

    # The next byte, left unread: the first byte of an instruction or a
    # representation tells which one it is.
    def peek
      raise Truncated.new("a byte wanted, none left", needed: @offset + 1) if eof?
      @bytes.getbyte(@offset) #: Integer
    end

    # RFC 7541 "Integer Representation" with a `prefix`-bit prefix. The bits
    # of the first byte above the prefix belong to the caller, which has
    # peeked at them already.
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

    # RFC 9204 "String Literals" with a `prefix`-bit prefix: the H bit, the
    # length as a (prefix - 1)-bit integer, then the octets, which come out
    # decoded when H says Huffman, frozen and binary. A string sure to be
    # longer than `max` octets raises TooLong before its octets are taken;
    # for a Huffman one that is when even 30-bit codes would decode to more.
    def string(prefix, max = nil)
      huffman = peek[prefix - 1] == 1
      length = integer(prefix - 1)
      if max
        shortest = huffman ? (length * 8 - 7) / 30 : length
        raise TooLong, "a string of at least #{shortest} octets, #{max} allowed" if shortest > max
      end
      octets = take(length)
      decoded = huffman ? Huffman.decode(octets) : octets.force_encoding(Encoding::BINARY)
      raise TooLong, "a string of #{decoded.bytesize} octets, #{max} allowed" if max && decoded.bytesize > max
      decoded.freeze
    end

    private def take(length)
      raise Truncated.new("#{length} bytes wanted, #{@limit - @offset} left", needed: @offset + length) if length > @limit - @offset
      octets = @bytes.byteslice(@offset, length) #: String
      @offset += length
      octets
    end

    private def u8
      byte = peek
      @offset += 1
      byte
    end
  end
end
