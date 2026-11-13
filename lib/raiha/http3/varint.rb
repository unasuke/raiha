# frozen_string_literal: true

module Raiha::Next::HTTP3
  # The variable-length integers of RFC 9000 "Variable-Length Integer
  # Encoding", which HTTP/3 takes for frame types, lengths and the fields
  # of frames: the two high bits of the first byte give the length, 1, 2,
  # 4 or 8 bytes. HTTP/3 has its own, as it does not know QUIC.
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

    # The value at `offset` of `bytes` and the offset past it; nil when the
    # bytes end before it does.
    def self.decode(bytes, offset = 0)
      first = bytes.getbyte(offset) or return nil
      size = 1 << (first >> 6)
      return nil if offset + size > bytes.bytesize
      value = case size
        when 1 then first
        when 2 then bytes.unpack1("n", offset:) & 0x3fff
        when 4 then bytes.unpack1("N", offset:) & 0x3fff_ffff
        else bytes.unpack1("Q>", offset:) & MAX
        end
      [value, offset + size]
    end
  end
end
