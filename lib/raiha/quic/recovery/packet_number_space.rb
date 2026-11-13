# frozen_string_literal: true

module Raiha::QUIC
  class Recovery
    # One packet number space (RFC 9000 "Packet Numbers"): :initial,
    # :handshake or :application_data. On the sending side it hands out the
    # packet numbers, now and then skipping one to catch a peer that
    # acknowledges what it never received, and keeps the record of each
    # packet sent until it is acknowledged, lost or discarded, in a Hash in
    # the order the packets were sent. On the receiving side it keeps the
    # packet numbers received, as the starts and ends of their ranges in
    # two Integer arrays, and the ECN marks they came with.
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
        # The packets of only ACKs sent since the last ack-eliciting one.
        @ack_only_tail = [] #: Array[Integer]
        @skip_after = nil #: Integer?
        @skipped = nil #: Integer?
        @ack_steps = 0
        @rejected_below = nil #: Integer?
        @ect0_sent = 0
        @ecn_counts = NO_ECN_COUNTS
        @received_starts = [] #: Array[Integer]
        @received_ends = [] #: Array[Integer]
        @ignore_below = 0
        @received_ecn = { ect0: 0, ect1: 0, ce: 0 } #: Hash[Symbol, Integer]
        @largest_received_at = nil #: Float?
        @largest_ack_eliciting_received = nil #: Integer?
        @unacked_ack_eliciting = 0
        @first_unacked_at = nil #: Float?
        @ack_deadline = nil #: Float?
        @ack_eliciting_threshold = 2
        @max_ack_delay = 0.0
      end

      # The ack-eliciting packets after which an ACK goes at once, and the
      # longest an ACK of an ack-eliciting packet waits (RFC 9000 "Sending ACK
      # Frames"). Values of the space, not constants, for ACK_FREQUENCY to
      # change one day; Initial and Handshake packets are always acknowledged
      # at once.
      attr_accessor :ack_eliciting_threshold
      attr_accessor :max_ack_delay
      # When an ACK must go, nil when none is owed.
      attr_reader :ack_deadline

      # Numbers below it are no longer kept and count as duplicates.
      attr_reader :ignore_below

      # Records the packet number received, with the ECN mark the datagram
      # came with; false for a duplicate, which is not counted (RFC 9000
      # "Packet Number Spaces"). The ranges are searched from the newest,
      # where most packets land, and a packet in order only moves the end of
      # the last range. Past MAX_ACK_RANGES ranges the oldest is let go.
      #
      # An ack-eliciting packet owes an ACK: at once in Initial and Handshake,
      # as the threshold's count of them, out of order, after a gap, or with
      # a CE mark; within max_ack_delay of the first one otherwise. `now` is
      # when the packet came, for the ACK Delay.
      def receive(packet_number, ecn:, ack_eliciting:, now:)
        return false if packet_number < @ignore_below
        largest = @received_ends.last
        return false unless record_received(packet_number)
        @received_ecn[ecn] += 1 if ecn != :not_ect
        @largest_received_at = now if largest.nil? || packet_number > largest
        owe_ack(packet_number, ce: ecn == :ce, now:) if ack_eliciting
        @ack_deadline = now if ecn == :ce && @unacked_ack_eliciting.positive?
        true
      end

      # An ACK of what was received went.
      def ack_sent
        @unacked_ack_eliciting = 0
        @first_unacked_at = nil
        @ack_deadline = nil
      end

      # Whether an ack-eliciting packet waits for an ACK, which can then ride
      # along with anything sent.
      def ack_owed? = @unacked_ack_eliciting.positive?

      # The ACK frame of what was received, nil before anything: at most
      # MAX_ACK_RANGES ranges, the delay since the largest came, and the ECN
      # counts when a packet was marked.
      def ack_frame(now:)
        largest_at = @largest_received_at or return nil
        Wire::Frame::Ack.new(ranges: received_ranges, delay: [now - largest_at, 0.0].max, ecn: received_ecn_counts)
      end

      private def owe_ack(packet_number, ce:, now:)
        @unacked_ack_eliciting += 1
        largest = @largest_ack_eliciting_received
        reordered = largest && packet_number < largest
        gap = largest && packet_number > largest && range_start(packet_number) > largest + 1
        @largest_ack_eliciting_received = packet_number if largest.nil? || packet_number > largest
        at_once = @name != :application_data || @unacked_ack_eliciting >= @ack_eliciting_threshold || reordered || gap || ce
        deadline = at_once ? now : (@first_unacked_at ||= now) + @max_ack_delay
        @ack_deadline = [@ack_deadline || deadline, deadline].min
      end

      # The start of the range received that holds `packet_number`.
      private def range_start(packet_number)
        index = @received_starts.size - 1
        index -= 1 while index.positive? && @received_starts.fetch(index) > packet_number
        @received_starts.fetch(index)
      end

      # Adds `packet_number` to the ranges; false when it is in one already.
      private def record_received(packet_number)
        starts = @received_starts
        ends = @received_ends
        index = starts.size - 1
        index -= 1 while index >= 0 && starts.fetch(index) > packet_number
        return false if index >= 0 && packet_number <= ends.fetch(index)
        after_left = index >= 0 && ends.fetch(index) + 1 == packet_number
        before_right = index + 1 < starts.size && starts.fetch(index + 1) - 1 == packet_number
        if after_left && before_right
          ends[index] = ends.fetch(index + 1)
          starts.delete_at(index + 1)
          ends.delete_at(index + 1)
        elsif after_left
          ends[index] = packet_number
        elsif before_right
          starts[index + 1] = packet_number
        else
          starts.insert(index + 1, packet_number)
          ends.insert(index + 1, packet_number)
        end
        if starts.size > MAX_ACK_RANGES
          starts.shift
          @ignore_below = ends.shift + 1
        end
        true
      end

      # The ranges received, the largest first, for an ACK frame.
      def received_ranges = @received_starts.each_with_index.map { |first, index| first..@received_ends.fetch(index) }.reverse!

      def largest_received = @received_ends.last

      # The ECN counts of the packets received, nil when none was marked.
      def received_ecn_counts
        return nil if @received_ecn.each_value.all?(&:zero?)
        Wire::Frame::Ack::ECNCounts.new(ect0: @received_ecn.fetch(:ect0), ect1: @received_ecn.fetch(:ect1), ce: @received_ecn.fetch(:ce))
      end

      # An ACK this end sent, whose largest was `largest`, was acknowledged:
      # the numbers up to it need not be acknowledged again (RFC 9000
      # "Limiting Ranges by Tracking ACK Frames").
      def acknowledged_up_to(largest)
        return if largest < @ignore_below
        @ignore_below = largest + 1
        while (first = @received_starts.first)
          last = @received_ends.fetch(0)
          if last <= largest
            @received_starts.shift
            @received_ends.shift
          else
            @received_starts[0] = largest + 1 if first <= largest
            break
          end
        end
      end

      NO_ECN_COUNTS = Wire::Frame::Ack::ECNCounts.new(ect0: 0, ect1: 0, ce: 0)

      # The least number the next packet will have, one more when a number
      # is left out first; not taken.
      def upcoming_packet_number = @next_packet_number

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

      # Whether a packet of only an ACK has gone since the last ack-eliciting
      # one.
      def acks_alone? = !@ack_only_tail.empty?

      # Leaves a packet number out after `packets` more packets.
      def skip_after(packets)
        raise ArgumentError, "a skip is pending already" if skipping?
        @skip_after = packets
      end

      # Keeps the record of a packet sent. Of the packets of only ACKs that
      # follow the last ack-eliciting one, which the peer may never
      # acknowledge, the latest MAX_NON_ACK_ELICITING_TAIL are kept (loss
      # recovery's design, "Limits").
      def add(packet)
        number = packet.packet_number
        @sent[number] = packet
        @largest_sent = number
        @ect0_sent += 1 if packet.ecn == :ect0
        if packet.ack_eliciting
          @ack_only_tail.clear
        elsif !packet.in_flight
          @ack_only_tail << number
          @sent.delete(@ack_only_tail.shift) if @ack_only_tail.size > MAX_NON_ACK_ELICITING_TAIL
        end
        return unless packet.in_flight && packet.ack_eliciting
        @time_of_last_ack_eliciting_packet = packet.time_sent
        @ack_eliciting_in_flight += 1
      end

      def sent?(packet_number) = @sent.key?(packet_number)

      # The oldest record in flight that elicits an ACK, nil when none.
      def oldest_ack_eliciting = @sent.each_value.find { |packet| packet.ack_eliciting && packet.in_flight }

      # The oldest record in flight that elicits an ACK and carries
      # something to send again, nil when none: a PING, a PMTU probe or a
      # probe of nothing but a PING carries nothing.
      def oldest_to_send_again = @sent.each_value.find { |packet| packet.ack_eliciting && packet.in_flight && !packet.duties.empty? }

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
      #
      # The time is compared by the same sum as the loss time, so that a
      # packet is lost at its loss time itself: `now - loss_delay` may round
      # below the time it was sent, which would set the timer again to the
      # time it ran out at.
      def detect_lost(loss_delay:, now:)
        largest = @largest_acked_packet
        @loss_time = nil
        lost = [] #: Array[SentPacket]
        return lost unless largest
        @sent.each_value do |packet|
          break if packet.packet_number > largest
          loss_time = packet.time_sent + loss_delay
          if largest >= packet.packet_number + PACKET_THRESHOLD
            lost << packet
            yield packet, :reordering_threshold
          elsif loss_time <= now
            lost << packet
            yield packet, :time_threshold
          else
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
        @received_starts.clear
        @received_ends.clear
        ack_sent
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
