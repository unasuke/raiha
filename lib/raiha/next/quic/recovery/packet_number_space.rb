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
      # The packets sent marked ECT(0), and the ECN counts of the last ACK
      # that passed validation.
      attr_reader :ect0_sent
      attr_accessor :ecn_counts

      def initialize(name)
        @name = name
        @next_packet_number = 0
        @largest_sent = nil #: Integer?
        @largest_acked_packet = nil #: Integer?
        @loss_time = nil #: Float?
        @time_of_last_ack_eliciting_packet = nil #: Float?
        @ack_eliciting_in_flight = 0
        @sent = {} #: Hash[Integer, SentPacket]
        @lost = {} #: Hash[Integer, SentPacket]
        @skip_after = nil #: Integer?
        @skipped = nil #: Integer?
        @ack_steps = 0
        @rejected_below = nil #: Integer?
        @ect0_sent = 0
        @ecn_counts = NO_ECN_COUNTS
      end

      NO_ECN_COUNTS = Wire::Frame::Ack::ECNCounts.new(ect0: 0, ect1: 0, ce: 0)

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
        @ect0_sent += 1 if packet.ecn == :ect0
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
        rejected = @rejected_below
        if rejected && ranges.fetch(-1).begin < rejected
          raise Violation.new("an ACK of a 0-RTT packet after 0-RTT was rejected", frame_type:)
        end
        @largest_acked_packet = [@largest_acked_packet || largest, largest].max
        @skipped = nil if skipped && largest > skipped
        acked = take_acknowledged(ranges)
        acked.each { |packet| @ack_eliciting_in_flight -= 1 if packet.in_flight && packet.ack_eliciting }
        acked
      end

      # Takes out the records lost (RFC 9002 "Detecting Lost Packets"): those
      # at least PACKET_THRESHOLD below the largest acknowledged, or sent
      # `loss_delay` or more before `now`. Each is yielded with its trigger,
      # :reordering_threshold or :time_threshold, and `loss_time` set to
      # when the next one would be lost by time.
      def detect_lost(loss_delay:, now:)
        largest = @largest_acked_packet
        @loss_time = nil
        lost = [] #: Array[SentPacket]
        return lost unless largest
        lost_send_time = now - loss_delay
        @sent.each_value do |packet|
          break if packet.packet_number > largest
          if largest >= packet.packet_number + PACKET_THRESHOLD
            lost << packet
            yield packet, :reordering_threshold
          elsif packet.time_sent <= lost_send_time
            lost << packet
            yield packet, :time_threshold
          else
            loss_time = packet.time_sent + loss_delay
            @loss_time = [@loss_time || loss_time, loss_time].min
          end
        end
        lost.each do |packet|
          @sent.delete(packet.packet_number)
          @lost[packet.packet_number] = packet
          @ack_eliciting_in_flight -= 1 if packet.in_flight && packet.ack_eliciting
        end
        @lost.shift while @lost.size > MAX_LOST_PACKETS
        lost
      end

      # Takes out the records declared lost that the ranges acknowledge
      # after all (loss recovery's design, "Lost packets kept").
      def take_spurious(ranges)
        @lost.each_value.select do |packet|
          number = packet.packet_number
          range = ranges.bsearch { |candidate| candidate.begin <= number }
          range&.cover?(number)
        end.each { |packet| @lost.delete(packet.packet_number) }
      end

      # Throws everything sent away, and gives the records that were still
      # waiting (RFC 9002 "Discarding Keys and Packet State"). The packet
      # numbers go on.
      def discard
        records = @sent.values
        @sent.clear
        @lost.clear
        @loss_time = nil
        @time_of_last_ack_eliciting_packet = nil
        @ack_eliciting_in_flight = 0
        records
      end

      # Throws away the records below `boundary`, the 0-RTT packets of a
      # rejected 0-RTT, and gives those that were still waiting; from now on
      # an ACK of any of them is PROTOCOL_VIOLATION (RFC 9001 "Rejecting
      # 0-RTT").
      def reject_below(boundary)
        @rejected_below = boundary
        @lost.delete_if { |number, _| number < boundary }
        rejected = @sent.values.select { |packet| packet.packet_number < boundary }
        rejected.each do |packet|
          @sent.delete(packet.packet_number)
          @ack_eliciting_in_flight -= 1 if packet.in_flight && packet.ack_eliciting
        end
        @loss_time = nil if @sent.empty?
        rejected
      end

      # Forgets the records declared lost that were sent before `time`.
      def forget_lost(before:)
        @lost.shift while (oldest = @lost.each_value.first) && oldest.time_sent < before
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
