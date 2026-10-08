# frozen_string_literal: true

module Raiha::Next::QUIC
  module Wire
    # RFC 9000 "Packet Number Encoding and Decoding": a packet carries only
    # the low 1 to 4 bytes of its number, and the receiver picks the full
    # number nearest to the one after the largest it has processed.
    module PacketNumber
      MAX = (1 << 62) - 1

      # The fewest bytes for `packet_number` whose window covers twice the
      # packets not yet acknowledged, the new one included (RFC 9000
      # appendix A.2). `largest_acked` is nil when the peer has acknowledged
      # none in this packet number space.
      def self.length(packet_number, largest_acked:)
        unacked = largest_acked ? packet_number - largest_acked : packet_number + 1
        raise ArgumentError, "packet #{packet_number} was acknowledged already" unless unacked.positive?
        length = ((2 * unacked - 1).bit_length + 7) / 8
        raise ArgumentError, "#{unacked} unacknowledged packets need #{length} bytes" if length > 4
        length
      end

      # The low `length` bytes of `packet_number`.
      def self.encode(packet_number, length)
        raise ArgumentError, "a packet number field is 1 to 4 bytes, not #{length}" unless length.between?(1, 4)
        [packet_number & 0xffff_ffff].pack("N").byteslice(4 - length, length)
      end

      # The full packet number of a packet whose `length`-byte field reads
      # `truncated` (RFC 9000 appendix A.3). `largest` is the largest
      # packet number processed in this packet number space, nil when none.
      def self.decode(truncated, length:, largest:)
        expected = largest ? largest + 1 : 0
        window = 1 << (8 * length)
        half_window = window / 2
        candidate = (expected & ~(window - 1)) | truncated
        if candidate <= expected - half_window && candidate <= MAX - window
          candidate + window
        elsif candidate > expected + half_window && candidate >= window
          candidate - window
        else
          candidate
        end
      end
    end
  end
end
