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
      # How many packet numbers or records the last `acknowledge` went
      # through.
      attr_reader :ack_steps

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
        @ack_steps = 0
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

      # Takes the ranges of an ACK frame of `frame_type`, from the largest
      # down, and gives the records they acknowledge for the first time,
      # taken out, in packet number order. An ACK of a packet never sent, the
      # skipped number among them, is PROTOCOL_VIOLATION (loss recovery's
      # design, "Validation"); one of packets acknowledged before is not.
      #
      # The ranges are first cut down to the records there are; then either
      # each number in them is looked up or the records are walked once
      # against them, whichever is less, so that wide ranges cost no more
      # than the records.
      def acknowledge(ranges, frame_type:)
        largest = ranges.first.end
        sent = @largest_sent
        if sent.nil? || largest > sent
          raise Violation.new("an ACK of packet #{largest}, never sent", frame_type:)
        end
        skipped = @skipped
        if skipped && ranges.any? { |range| range.cover?(skipped) }
          raise Violation.new("an ACK of packet #{skipped}, skipped", frame_type:)
        end
        @largest_acked_packet = [@largest_acked_packet || largest, largest].max
        @skipped = nil if skipped && largest > skipped
        acked = take_acknowledged(ranges)
        acked.each { |packet| @ack_eliciting_in_flight -= 1 if packet.in_flight && packet.ack_eliciting }
        acked
      end

      private def take_acknowledged(ranges)
        @ack_steps = 0
        oldest = @sent.each_key.first
        return [] unless oldest
        clipped = ranges.filter_map do |range|
          low = [range.begin, oldest].max
          low..range.end if low <= range.end
        end
        width = clipped.sum { |range| range.end - range.begin + 1 }
        width <= @sent.size ? look_up(clipped) : walk(clipped)
      end

      # Each number of the ranges, from the smallest.
      private def look_up(ranges)
        acked = [] #: Array[SentPacket]
        ranges.reverse_each do |range|
          range.each do |number|
            @ack_steps += 1
            packet = @sent.delete(number)
            acked << packet if packet
          end
        end
        acked
      end

      # The records in order, against the ranges from the smallest, up to
      # the largest range.
      private def walk(ranges)
        acked = [] #: Array[SentPacket]
        ascending = ranges.reverse
        index = 0
        @sent.each_key do |number|
          @ack_steps += 1
          index += 1 while index < ascending.size && ascending.fetch(index).end < number
          break if index == ascending.size
          acked << @sent.fetch(number) if ascending.fetch(index).cover?(number)
        end
        acked.each { |packet| @sent.delete(packet.packet_number) }
        acked
      end
    end
  end
end
