# frozen_string_literal: true

module Raiha
  module HTTP3
    module QPACK
      # RFC 9204 Section 4.1.1 / RFC 7541 Section 5.1: Integer encoding with N-bit prefix
      module Integer
        # Encode an integer into bytes. prefix_bits is the number of bits in the first byte
        # available for the integer. prefix_flags is the value to OR into the high bits of
        # the first byte (must not overlap with the prefix_bits).
        def self.encode(value, prefix_bits, prefix_flags = 0)
          max_prefix_value = (1 << prefix_bits) - 1

          if value < max_prefix_value
            return [prefix_flags | value].pack("C")
          end

          bytes = [prefix_flags | max_prefix_value].pack("C")
          remaining = value - max_prefix_value
          while remaining >= 128
            bytes << [(remaining & 0x7f) | 0x80].pack("C")
            remaining >>= 7
          end
          bytes << [remaining].pack("C")
          bytes
        end

        # Decode an integer starting from the current buffer position. prefix_bits indicates
        # how many bits of the first byte belong to the integer (the upper bits are flags).
        # The first byte has already been peeked; this method reads it and possibly more.
        def self.decode(buffer, prefix_bits)
          max_prefix_value = (1 << prefix_bits) - 1
          first_byte = buffer.read_uint8
          value = first_byte & max_prefix_value

          return value if value < max_prefix_value

          multiplier = 0
          loop do
            byte = buffer.read_uint8
            value += (byte & 0x7f) << multiplier
            break if (byte & 0x80) == 0
            multiplier += 7
          end
          value
        end
      end
    end
  end
end
