# frozen_string_literal: true

require_relative "../protocol/packet_number"
require_relative "../wire/frames/ack_frame"
require_relative "../timer"

module Raiha::Quic
  module AckHandler
    class ReceivedPacketHandler
      class PacketNumberSpaceState
        attr_reader :largest_received
        attr_reader :received_packet_numbers
        attr_reader :ack_eliciting_count
        attr_accessor :ack_alarm

        def initialize
          @largest_received = nil
          @received_packet_numbers = []
          @largest_received_time = nil
          @ack_eliciting_count = 0
          @ack_alarm = Timer.new
        end

        def record_received(packet_number, ack_eliciting:)
          @received_packet_numbers << packet_number

          if @largest_received.nil? || packet_number > @largest_received
            @largest_received = packet_number
            @largest_received_time = Time.now
          end

          @ack_eliciting_count += 1 if ack_eliciting
        end

        def should_send_ack?
          @ack_eliciting_count >= 2 || @ack_alarm.expired?
        end

        def reset_ack_state
          @ack_eliciting_count = 0
          @ack_alarm.reset
        end

        def largest_received_time
          @largest_received_time
        end
      end

      MAX_ACK_DELAY = 25

      def initialize
        @spaces = {
          Protocol::PacketNumberSpace::INITIAL => PacketNumberSpaceState.new,
          Protocol::PacketNumberSpace::HANDSHAKE => PacketNumberSpaceState.new,
          Protocol::PacketNumberSpace::APPLICATION_DATA => PacketNumberSpaceState.new,
        }
      end

      def received_packet(packet_number:, pn_space:, ack_eliciting:)
        space = @spaces[pn_space]

        return false if space.received_packet_numbers.include?(packet_number)

        space.record_received(packet_number, ack_eliciting: ack_eliciting)

        if ack_eliciting && !space.ack_alarm.active?
          space.ack_alarm.set(MAX_ACK_DELAY / 1000.0)
        end

        true
      end

      def should_send_ack?(pn_space)
        # RFC 9002 Section 6.2: ack-eliciting Initial and Handshake packets must be acknowledged immediately
        if pn_space == Protocol::PacketNumberSpace::INITIAL || pn_space == Protocol::PacketNumberSpace::HANDSHAKE
          return @spaces[pn_space].ack_eliciting_count > 0
        end

        @spaces[pn_space].should_send_ack?
      end

      def get_ack_frame(pn_space)
        space = @spaces[pn_space]
        return nil if space.received_packet_numbers.empty?

        ranges = compute_ack_ranges(space.received_packet_numbers.sort.reverse)

        frame = Wire::Frames::AckFrame.new
        frame.largest_acknowledged = space.largest_received
        frame.ack_delay = compute_ack_delay(space)
        frame.ack_ranges = ranges

        space.reset_ack_state

        frame
      end

      def get_alarm_timeout
        earliest = nil

        @spaces.each_value do |space|
          next unless space.ack_alarm.active?
          next if earliest && space.ack_alarm.deadline >= earliest

          earliest = space.ack_alarm.deadline
        end

        earliest
      end

      private def compute_ack_ranges(sorted_packet_numbers)
        return [] if sorted_packet_numbers.empty?

        ranges = []
        current_start = sorted_packet_numbers.first
        current_end = sorted_packet_numbers.first

        sorted_packet_numbers[1..].each do |packet_number|
          if packet_number == current_end - 1
            current_end = packet_number
          else
            ranges << Wire::Frames::AckFrame::AckRange.new(
              gap: current_end - packet_number - 2,
              ack_range_length: current_start - current_end
            )
            current_start = packet_number
            current_end = packet_number
          end
        end

        ranges << Wire::Frames::AckFrame::AckRange.new(
          gap: 0,
          ack_range_length: current_start - current_end
        )

        ranges
      end

      private def compute_ack_delay(space)
        return 0 unless space.largest_received_time

        delay = Time.now - space.largest_received_time
        (delay * 1_000_000).to_i # microseconds
      end
    end
  end
end
