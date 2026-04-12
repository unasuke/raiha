# frozen_string_literal: true

module Raiha::Quic
  module Protocol
    class PacketNumber
      MAX_VALUE = (1 << 62) - 1

      attr_reader :value

      def initialize(value)
        @value = value
        validate!
      end

      def increment
        PacketNumber.new(@value + 1)
      end

      def -(other)
        @value - other.value
      end

      def <=>(other)
        @value <=> other.value
      end
      include Comparable

      # RFC 9000 Section 17.1 - Packet Number Encoding
      def encode(largest_acked)
        num_unacked = @value - (largest_acked || 0)

        if num_unacked < (1 << 7)
          { bytes: 1, encoded: [@value & 0xff].pack("C") }
        elsif num_unacked < (1 << 14)
          { bytes: 2, encoded: [@value & 0xffff].pack("n") }
        elsif num_unacked < (1 << 22)
          { bytes: 3, encoded: [(@value >> 16) & 0xff, (@value >> 8) & 0xff, @value & 0xff].pack("CCC") }
        else
          { bytes: 4, encoded: [@value & 0xffffffff].pack("N") }
        end
      end

      # RFC 9000 Section A.3 - Sample Packet Number Decoding
      def self.decode(truncated_pn, pn_nbits, largest_pn)
        expected_pn = largest_pn + 1
        pn_win = 1 << pn_nbits
        pn_hwin = pn_win / 2
        pn_mask = pn_win - 1

        candidate_pn = (expected_pn & ~pn_mask) | truncated_pn

        if candidate_pn <= expected_pn - pn_hwin && candidate_pn < (1 << 62) - pn_win
          self.new(candidate_pn + pn_win)
        elsif candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win
          self.new(candidate_pn - pn_win)
        else
          self.new(candidate_pn)
        end
      end

      private def validate!
        raise ArgumentError, "Packet number overflow" if @value > MAX_VALUE
        raise ArgumentError, "Packet number must be non-negative" if @value < 0
      end
    end

    module PacketNumberSpace
      INITIAL = :initial
      HANDSHAKE = :handshake
      APPLICATION_DATA = :application_data

      ALL = [INITIAL, HANDSHAKE, APPLICATION_DATA].freeze
    end
  end
end
