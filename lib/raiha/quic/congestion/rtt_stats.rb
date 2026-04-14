# frozen_string_literal: true

module Raiha::Quic
  module Congestion
    # RFC 9002 Section 5 - Estimating the Round-Trip Time
    class RTTStats
      INITIAL_RTT = 0.333 # 333ms

      attr_reader :min_rtt
      attr_reader :latest_rtt
      attr_reader :smoothed_rtt
      attr_reader :rtt_var
      attr_reader :max_ack_delay

      def initialize(max_ack_delay: 0.025)
        @min_rtt = Float::INFINITY
        @latest_rtt = 0
        @smoothed_rtt = INITIAL_RTT
        @rtt_var = INITIAL_RTT / 2
        @max_ack_delay = max_ack_delay
        @first_sample = true
      end

      def update_rtt(rtt_sample, ack_delay)
        @latest_rtt = rtt_sample
        @min_rtt = [@min_rtt, rtt_sample].min

        adjusted_rtt = if @min_rtt + ack_delay < @latest_rtt
          @latest_rtt - ack_delay
        else
          @latest_rtt
        end

        if @first_sample
          @smoothed_rtt = adjusted_rtt
          @rtt_var = adjusted_rtt / 2
          @first_sample = false
        else
          rtt_var_sample = (@smoothed_rtt - adjusted_rtt).abs
          @rtt_var = (3.0 / 4.0) * @rtt_var + (1.0 / 4.0) * rtt_var_sample
          @smoothed_rtt = (7.0 / 8.0) * @smoothed_rtt + (1.0 / 8.0) * adjusted_rtt
        end
      end

      # RFC 9002 Section 6.2.1
      def pto
        @smoothed_rtt + [4 * @rtt_var, 0.001].max + @max_ack_delay
      end

      # RFC 9002 Section 6.1.2
      def loss_delay
        time_threshold = 9.0 / 8.0
        granularity = 0.001
        [time_threshold * [@smoothed_rtt, @latest_rtt].max, granularity].max
      end

      def reset
        @min_rtt = Float::INFINITY
        @first_sample = true
      end

      def has_samples?
        !@first_sample
      end
    end
  end
end
