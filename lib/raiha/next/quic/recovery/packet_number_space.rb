# frozen_string_literal: true

module Raiha::Next::QUIC
  class Recovery
    # One packet number space (RFC 9000 "Packet Numbers"): :initial,
    # :handshake or :application_data. On the sending side it hands out the
    # packet numbers, now and then skipping one to catch a peer that
    # acknowledges what it never received, and keeps the record of each
    # packet sent until it is acknowledged, lost or discarded, in a Hash in
    # the order the packets were sent.
    class PacketNumberSpace
      attr_reader :name
      # The largest packet number sent, nil before any.
      attr_reader :largest_sent
      # The largest packet number the peer acknowledged, nil before any.
      attr_reader :largest_acked_packet
      # When the next packet can be declared lost by time, nil when none
      # can.
      attr_accessor :loss_time
      attr_reader :time_of_last_ack_eliciting_packet
      # The ack-eliciting packets in flight in this space.
      attr_reader :ack_eliciting_in_flight
      # The packet number skipped and not yet shown to be one the peer
      # leaves out of its ACKs, nil when none.
      attr_reader :skipped

      def initialize(name)
        @name = name
        @next_packet_number = 0
        @largest_sent = nil #: Integer?
        @largest_acked_packet = nil #: Integer?
        @loss_time = nil #: Float?
        @time_of_last_ack_eliciting_packet = nil #: Float?
        @ack_eliciting_in_flight = 0
        @sent = {} #: Hash[Integer, SentPacket]
        @skip_after = nil #: Integer?
        @skipped = nil #: Integer?
      end

      # The packet number for the next packet. After `skip_after`'s count
      # of packets, one number is left out first.
      def next_packet_number
        number = @next_packet_number
        case @skip_after
        when 0
          @skipped = number
          number += 1
          @skip_after = nil
        when Integer then @skip_after -= 1 # steep:ignore
        end
        @next_packet_number = number + 1
        number
      end

      # Whether a skip is to come or has yet to be shown.
      def skipping? = !@skip_after.nil? || !@skipped.nil?

      # Leaves a packet number out after `packets` more packets.
      def skip_after(packets)
        raise ArgumentError, "a skip is pending already" if skipping?
        @skip_after = packets
      end

      def add(packet)
        @sent[packet.packet_number] = packet
        @largest_sent = packet.packet_number
        return unless packet.in_flight && packet.ack_eliciting
        @time_of_last_ack_eliciting_packet = packet.time_sent
        @ack_eliciting_in_flight += 1
      end

      def sent?(packet_number) = @sent.key?(packet_number)
    end
  end
end
