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

      # on_packet_lost: called with (lost_packet, pn_space) whenever a packet
      # is declared lost. The caller (Connection) is responsible for
      # inspecting the packet's frames and re-enqueueing anything that should
      # be retransmitted (RFC 9002 §6.3.1).
      def initialize(congestion_controller: nil, rtt_stats: nil, on_packet_lost: nil)
        @congestion_controller = congestion_controller
        @rtt_stats = rtt_stats
        @on_packet_lost = on_packet_lost

        @spaces = {
          Protocol::PacketNumberSpace::INITIAL => PacketNumberSpace.new(:initial),
          Protocol::PacketNumberSpace::HANDSHAKE => PacketNumberSpace.new(:handshake),
          Protocol::PacketNumberSpace::APPLICATION_DATA => PacketNumberSpace.new(:application_data),
        }

        @bytes_in_flight = 0
        @pto_count = 0
        @time_of_last_ack_eliciting_packet = nil
        @alarm = Timer.new
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
        @pto_count = 0
      end

      def get_alarm_timeout
        @alarm.deadline
      end

      # Earliest deadline at which any unacked packet, in any PN space, will
      # cross the RFC 9002 §6.1.2 time-threshold and need re-examination.
      # Returns nil if nothing is armed.
      def loss_detection_deadline
        deadlines = @spaces.values.map(&:loss_time).compact
        return nil if deadlines.empty?

        deadlines.min
      end

      # App-driven timer firing. Re-runs detect_lost_packets against every
      # space so any ack-eliciting packet whose sent_time + loss_delay has
      # passed is declared lost, even without a fresh ACK.
      def on_loss_detection_timeout(now: Time.now)
        @spaces.each_value { |space| detect_lost_packets(space, now: now) }
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
