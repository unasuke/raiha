# frozen_string_literal: true

module Raiha::Quic
  module Congestion
    class Pacer
      PACING_GAIN = 1.25

      def initialize(congestion_controller:, rtt_stats:)
        @congestion_controller = congestion_controller
        @rtt_stats = rtt_stats
        @last_sent_time = nil
        @budget = 0
      end

      def can_send?(bytes)
        update_budget
        @budget >= bytes || @congestion_controller.in_slow_start?
      end

      def on_packet_sent(bytes)
        @budget -= bytes
        @last_sent_time = Time.now
      end

      def time_until_send(bytes)
        return 0 if @congestion_controller.in_slow_start?

        update_budget
        return 0 if @budget >= bytes

        bytes_needed = bytes - @budget
        send_rate = pacing_rate
        return 0 if send_rate == 0 || send_rate == Float::INFINITY

        bytes_needed.to_f / send_rate
      end

      def pacing_rate
        return Float::INFINITY if @rtt_stats.smoothed_rtt == 0

        congestion_window = @congestion_controller.congestion_window
        (congestion_window * PACING_GAIN / @rtt_stats.smoothed_rtt).to_i
      end

      private def update_budget
        now = Time.now

        if @last_sent_time
          elapsed = now - @last_sent_time
          rate = pacing_rate
          @budget += (rate * elapsed).to_i if rate < Float::INFINITY
        end

        max_budget = @congestion_controller.congestion_window / 4
        @budget = [@budget, max_budget].min

        @last_sent_time = now
      end
    end
  end
end
