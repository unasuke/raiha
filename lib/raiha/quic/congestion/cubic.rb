# frozen_string_literal: true

require_relative "rtt_stats"

module Raiha::Quic
  module Congestion
    # RFC 9002 Section 7 - Congestion Control
    # RFC 9438 - CUBIC
    class Cubic
      INITIAL_WINDOW_PACKETS = 10
      MIN_WINDOW_PACKETS = 2
      BETA_CUBIC = 0.7
      C_CUBIC = 0.4
      MAX_DATAGRAM_SIZE = 1200

      attr_reader :congestion_window
      attr_reader :bytes_in_flight
      attr_reader :slow_start_threshold

      def initialize(max_datagram_size: MAX_DATAGRAM_SIZE, rtt_stats: nil)
        @max_datagram_size = max_datagram_size
        @rtt_stats = rtt_stats
        @congestion_window = INITIAL_WINDOW_PACKETS * @max_datagram_size
        @slow_start_threshold = Float::INFINITY
        @bytes_in_flight = 0

        @w_max = 0
        @k = 0
        @epoch_start = nil
        @w_last_max = 0

        @in_slow_start = true
      end

      def on_packet_sent(bytes)
        @bytes_in_flight += bytes
      end

      def on_packets_acked(packets)
        packets.each do |packet|
          on_packet_acked(packet.size)
        end
      end

      def on_packet_lost(packet)
        @bytes_in_flight -= packet.size if @bytes_in_flight >= packet.size

        @epoch_start = nil
        if @congestion_window < @w_last_max
          @w_last_max = (@congestion_window * (1 + BETA_CUBIC) / 2).to_i
        else
          @w_last_max = @congestion_window
        end

        @w_max = @congestion_window
        @congestion_window = (@congestion_window * BETA_CUBIC).to_i
        @congestion_window = [min_congestion_window, @congestion_window].max
        @slow_start_threshold = @congestion_window
        @in_slow_start = false
      end

      def can_send?
        @bytes_in_flight < @congestion_window
      end

      def available_congestion_window
        if @congestion_window > @bytes_in_flight
          @congestion_window - @bytes_in_flight
        else
          0
        end
      end

      def in_slow_start?
        @in_slow_start
      end

      def in_congestion_avoidance?
        !@in_slow_start && @congestion_window >= @slow_start_threshold
      end

      private def on_packet_acked(acked_bytes)
        @bytes_in_flight -= acked_bytes if @bytes_in_flight >= acked_bytes

        if @in_slow_start
          @congestion_window += acked_bytes

          if @congestion_window >= @slow_start_threshold
            @in_slow_start = false
            @epoch_start = nil
          end
        else
          cubic_increase(acked_bytes)
        end
      end

      private def cubic_increase(acked_bytes)
        @epoch_start ||= Time.now
        elapsed = Time.now - @epoch_start

        if @w_max > 0
          @k = ((@w_max * (1 - BETA_CUBIC)) / (C_CUBIC * @max_datagram_size)) ** (1.0 / 3.0)
        else
          @k = 0
        end

        w_cubic = C_CUBIC * ((elapsed - @k) ** 3) * @max_datagram_size + @w_max

        rtt = @rtt_stats&.smoothed_rtt || RTTStats::INITIAL_RTT
        w_est = @w_max * BETA_CUBIC + (3 * (1 - BETA_CUBIC) / (1 + BETA_CUBIC)) * (elapsed / rtt) * @max_datagram_size

        target = w_cubic < w_est ? w_est : w_cubic

        if target > @congestion_window
          increment = (target - @congestion_window) * acked_bytes / @congestion_window
          @congestion_window += [increment.to_i, 1].max
        end
      end

      private def min_congestion_window
        MIN_WINDOW_PACKETS * @max_datagram_size
      end
    end
  end
end
