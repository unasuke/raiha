# frozen_string_literal: true

require_relative "../protocol/packet_number"
require_relative "../timer"

module Raiha::Quic
  module AckHandler
    class SentPacketHandler
      class PacketNumberSpace
        attr_reader :encryption_level
        attr_reader :sent_packets
        attr_reader :largest_acked
        attr_accessor :loss_time

        def initialize(encryption_level)
          @encryption_level = encryption_level
          @sent_packets = {}
          @largest_acked = nil
          @loss_time = nil #: Time?
          @largest_sent = -1
        end

        def next_packet_number
          @largest_sent += 1
          Protocol::PacketNumber.new(@largest_sent)
        end

        def add_sent_packet(packet)
          @sent_packets[packet.packet_number.value] = packet
        end

        def remove_sent_packet(packet_number)
          @sent_packets.delete(packet_number)
        end

        def update_largest_acked(value)
          @largest_acked = value
        end
      end

      SentPacket = Data.define(
        :packet_number,
        :frames,
        :sent_time,
        :size,
        :ack_eliciting,
        :in_flight
      )

      attr_reader :bytes_in_flight

      attr_reader :pto_count

      # on_packet_lost: called with (lost_packet, pn_space) whenever a packet
      # is declared lost. The caller (Connection) is responsible for
      # inspecting the packet's frames and re-enqueueing anything that should
      # be retransmitted (RFC 9002 §6.3.1).
      #
      # on_pto_fired: called with no arguments whenever the PTO alarm fires
      # (RFC 9002 §6.2.4). The caller should emit one or two ack-eliciting
      # probe packets (typically a PING).
      def initialize(congestion_controller: nil, rtt_stats: nil, on_packet_lost: nil, on_pto_fired: nil)
        @congestion_controller = congestion_controller
        @rtt_stats = rtt_stats
        @on_packet_lost = on_packet_lost
        @on_pto_fired = on_pto_fired

        @spaces = {
          Protocol::PacketNumberSpace::INITIAL => PacketNumberSpace.new(:initial),
          Protocol::PacketNumberSpace::HANDSHAKE => PacketNumberSpace.new(:handshake),
          Protocol::PacketNumberSpace::APPLICATION_DATA => PacketNumberSpace.new(:application_data),
        }

        @bytes_in_flight = 0
        @pto_count = 0
        @time_of_last_ack_eliciting_packet = nil #: Time?
        @alarm = Timer.new
        # Per-PN-space ECN-CE count last observed on ACK_ECN frames from
        # the peer (RFC 9002 §B.4 ProcessECN). An increase is treated as a
        # congestion event.
        @last_peer_ce_counts = {
          Protocol::PacketNumberSpace::INITIAL => 0,
          Protocol::PacketNumberSpace::HANDSHAKE => 0,
          Protocol::PacketNumberSpace::APPLICATION_DATA => 0,
        }
      end

      def get_next_packet_number(pn_space)
        @spaces[pn_space].next_packet_number
      end

      def sent_packet(packet_number:, frames:, size:, ack_eliciting:, pn_space:, sent_time: Time.now)
        space = @spaces[pn_space]

        sent = SentPacket.new(
          packet_number: packet_number,
          frames: frames,
          sent_time: sent_time,
          size: size,
          ack_eliciting: ack_eliciting,
          in_flight: ack_eliciting,
        )

        space.add_sent_packet(sent)

        if ack_eliciting
          @time_of_last_ack_eliciting_packet = sent_time
          @bytes_in_flight += size
          @congestion_controller&.on_packet_sent(size)
        end
      end

      def received_ack(ack_frame, pn_space:, ack_delay: 0, now: Time.now)
        space = @spaces[pn_space]

        return unless space.largest_acked.nil? ||
                      ack_frame.largest_acknowledged > space.largest_acked

        space.update_largest_acked(ack_frame.largest_acknowledged)

        newly_acked_packets = detect_and_remove_acked_packets(ack_frame, space)
        return if newly_acked_packets.empty?

        latest_acked = newly_acked_packets.max_by { |packet| packet.packet_number.value }
        if latest_acked.packet_number.value == ack_frame.largest_acknowledged && @rtt_stats
          rtt_sample = now - latest_acked.sent_time
          @rtt_stats.update_rtt(rtt_sample, ack_delay)
        end

        detect_lost_packets(space, now: now)
        @congestion_controller&.on_packets_acked(newly_acked_packets)
        process_ecn(ack_frame, pn_space: pn_space)
        @pto_count = 0
      end

      # RFC 9002 §B.4 ProcessECN: if the peer's ACK_ECN reports more CE
      # marks than we've previously seen for this space, that is a new
      # congestion event (same treatment as a packet-loss event).
      private def process_ecn(ack_frame, pn_space:)
        return unless ack_frame.ecn_counts

        reported_ce = ack_frame.ecn_counts[:ecn_ce] || 0
        return unless reported_ce > @last_peer_ce_counts[pn_space]

        @last_peer_ce_counts[pn_space] = reported_ce
        @congestion_controller&.on_ecn_ce
      end

      def get_alarm_timeout
        @alarm.deadline
      end

      # Drop every sent-but-unacked packet for the given packet-number
      # space and adjust bytes_in_flight accordingly. Used when an entire
      # flight needs to be forgotten rather than acked or declared lost —
      # e.g. on a client-side RFC 9000 §17.2.5.2 Retry, where the Initial
      # we already sent was never meant for the server that accepted us.
      def discard_space(pn_space)
        space = @spaces[pn_space]
        return unless space

        space.sent_packets.each_value do |packet|
          @bytes_in_flight -= packet.size if packet.in_flight
        end
        space.sent_packets.clear
        space.loss_time = nil
      end

      # Earliest deadline at which this handler wants to be woken up: the
      # smaller of the time-threshold loss deadline (§6.1.2) and the PTO
      # deadline (§6.2.1). Per §A.9, loss_time always wins when set.
      def loss_detection_deadline
        loss_time = @spaces.values.map(&:loss_time).compact.min
        return loss_time if loss_time

        pto_deadline
      end

      # App-driven timer firing. Distinguishes the two phases per RFC 9002
      # §A.9 OnLossDetectionTimeout:
      #   - if any loss_time is set, run time-threshold loss detection;
      #   - otherwise this is a PTO firing: bump pto_count (exponential
      #     backoff) and signal the caller to send probe packets.
      def on_loss_detection_timeout(now: Time.now)
        earliest_loss_time = @spaces.values.map(&:loss_time).compact.min
        if earliest_loss_time
          @spaces.each_value { |space| detect_lost_packets(space, now: now) }
          return
        end

        return unless ack_eliciting_in_flight?

        @pto_count += 1
        @on_pto_fired&.call
      end

      # RFC 9002 §6.2.1: PTO = smoothed_rtt + max(4*rttvar, kGranularity) +
      # max_ack_delay. We arm the alarm relative to the most recent
      # ack-eliciting packet sent in any space and back off exponentially
      # based on pto_count.
      def pto_deadline
        return nil unless @time_of_last_ack_eliciting_packet
        return nil unless ack_eliciting_in_flight?

        base = @rtt_stats ? @rtt_stats.pto : 0.333 + 0.025
        @time_of_last_ack_eliciting_packet + base * (2**@pto_count)
      end

      private def ack_eliciting_in_flight?
        @spaces.each_value do |space|
          space.sent_packets.each_value do |packet|
            return true if packet.ack_eliciting
          end
        end
        false
      end

      private def detect_and_remove_acked_packets(ack_frame, space)
        acked = [] #: Array[untyped]

        acknowledged_packet_numbers(ack_frame).each do |packet_number|
          sent = space.remove_sent_packet(packet_number)
          next unless sent

          @bytes_in_flight -= sent.size if sent.in_flight
          acked << sent
        end

        acked
      end

      private def acknowledged_packet_numbers(ack_frame)
        numbers = [] #: Array[Integer]
        largest = ack_frame.largest_acknowledged

        ack_frame.ack_ranges.each_with_index do |range, index|
          if index == 0
            (range.ack_range_length + 1).times do |i|
              numbers << largest - i
            end
          else
            largest = numbers.last - range.gap - 2
            (range.ack_range_length + 1).times do |i|
              numbers << largest - i
            end
          end
        end

        numbers
      end

      # RFC 9002 §6.1: a packet older than largest_acked is declared lost if
      # either the packet-number gap crosses kPacketThreshold (3) or
      # sent_time + loss_delay is in the past. The earliest remaining
      # candidate's deadline becomes the space's next loss_time.
      private def detect_lost_packets(space, now: Time.now)
        return unless space.largest_acked

        packet_threshold = 3
        loss_delay = @rtt_stats ? @rtt_stats.loss_delay : 0.333
        time_threshold = now - loss_delay
        lost_packets = [] #: Array[untyped]
        next_loss_time = nil #: Time?

        space.sent_packets.each do |packet_number, sent|
          next unless packet_number < space.largest_acked

          if (space.largest_acked - packet_number) >= packet_threshold ||
             sent.sent_time <= time_threshold
            lost_packets << sent
          else
            deadline = sent.sent_time + loss_delay
            next_loss_time = deadline if next_loss_time.nil? || deadline < next_loss_time
          end
        end

        space.loss_time = next_loss_time

        pn_space = pn_space_for(space)

        lost_packets.each do |packet|
          space.remove_sent_packet(packet.packet_number.value)
          if packet.in_flight
            @bytes_in_flight -= packet.size
            @congestion_controller&.on_packet_lost(packet)
          end
          @on_packet_lost&.call(packet, pn_space)
        end

        lost_packets
      end

      private def pn_space_for(space)
        @spaces.each { |key, value| return key if value.equal?(space) }
        nil
      end
    end
  end
end
