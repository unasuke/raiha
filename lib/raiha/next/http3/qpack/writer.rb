# frozen_string_literal: true

require_relative "reader"

module Raiha::Next::HTTP3::QPACK
  # Writes the primitives of RFC 9204 "Primitives" into a binary String.
  class Writer
    def initialize
      @buffer = String.new(encoding: Encoding::BINARY)
    end

    # RFC 7541 "Integer Representation" with a `prefix`-bit prefix, under
    # `flags`, the bits of the first byte above the prefix.
    def integer(value, prefix, flags = 0)
      unless value.is_a?(Integer) && value.between?(0, Reader::MAX_INTEGER)
        raise ArgumentError, "a QPACK integer is 0..2^62-1, not #{value.inspect}"
      end
      mask = (1 << prefix) - 1
      return tap { @buffer << (flags | value) } if value < mask
      @buffer << (flags | mask)
      value -= mask
      while value >= 0x80
        @buffer << ((value & 0x7f) | 0x80)
        value >>= 7
      end
      tap { @buffer << value }
    end

    # RFC 9204 "String Literals" with a `prefix`-bit prefix, under `flags`:
    # in the Huffman code when that is shorter, as it is otherwise.
    def string(value, prefix, flags = 0)
      huffman_length = Huffman.encoded_length(value)
      if huffman_length < value.bytesize
        integer(huffman_length, prefix - 1, flags | (1 << (prefix - 1)))
        tap { @buffer << Huffman.encode(value) }
      else
        integer(value.bytesize, prefix - 1, flags)
        tap { @buffer.append_as_bytes(value) }
      end
    end

    def to_s = @buffer
  end
end
