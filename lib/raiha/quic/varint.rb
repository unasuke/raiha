# frozen_string_literal: true

module Raiha::Quic
  # RFC 9000 Section 16 - Variable-Length Integer Encoding
  #
  # +------+--------+-------------+-----------------------+
  # | 2MSB | Length | Usable Bits | Range                 |
  # +------+--------+-------------+-----------------------+
  # | 00   | 1      | 6           | 0-63                  |
  # | 01   | 2      | 14          | 0-16383               |
  # | 10   | 4      | 30          | 0-1073741823          |
  # | 11   | 8      | 62          | 0-4611686018427387903 |
  # +------+--------+-------------+-----------------------+
  module Varint
    MAX_VALUE = (1 << 62) - 1
    MAX_1_BYTE = 63
    MAX_2_BYTE = 16383
    MAX_4_BYTE = 1073741823

    class << self
      def encode(value)
        raise ArgumentError, "Value too large for varint" if value > MAX_VALUE
        raise ArgumentError, "Value must be non-negative" if value < 0

        if value <= MAX_1_BYTE
          [value].pack("C")
        elsif value <= MAX_2_BYTE
          [0x40 | (value >> 8), value & 0xff].pack("CC")
        elsif value <= MAX_4_BYTE
          [0x80 | (value >> 24), (value >> 16) & 0xff,
           (value >> 8) & 0xff, value & 0xff].pack("CCCC")
        else
          [0xc0 | (value >> 56), (value >> 48) & 0xff,
           (value >> 40) & 0xff, (value >> 32) & 0xff,
           (value >> 24) & 0xff, (value >> 16) & 0xff,
           (value >> 8) & 0xff, value & 0xff].pack("CCCCCCCC")
        end
      end

      def decode(io)
        first_byte = io.read(1).unpack1("C")
        prefix = first_byte >> 6

        case prefix
        when 0
          first_byte & 0x3f
        when 1
          second_byte = io.read(1).unpack1("C")
          ((first_byte & 0x3f) << 8) | second_byte
        when 2
          rest = io.read(3).unpack("CCC")
          ((first_byte & 0x3f) << 24) | (rest[0] << 16) | (rest[1] << 8) | rest[2]
        when 3
          rest = io.read(7).unpack("CCCCCCC")
          ((first_byte & 0x3f) << 56) | (rest[0] << 48) | (rest[1] << 40) |
          (rest[2] << 32) | (rest[3] << 24) | (rest[4] << 16) |
          (rest[5] << 8) | rest[6]
        end
      end

      def byte_size(value)
        if value <= MAX_1_BYTE then 1
        elsif value <= MAX_2_BYTE then 2
        elsif value <= MAX_4_BYTE then 4
        else 8
        end
      end
    end
  end
end
