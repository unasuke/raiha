# frozen_string_literal: true

module Raiha::Next::QUIC
  class Recovery
    # The RTT of a path (RFC 9002 "Estimating the Round-Trip Time"): the
    # latest sample, the smoothed RTT and its variation, and the minimum,
    # with the time of the first sample.
    class RttEstimator
      # Seconds; 0 before the first sample.
      attr_reader :latest_rtt
      attr_reader :smoothed_rtt
      attr_reader :rttvar
      # nil before the first sample.
      attr_reader :min_rtt
      attr_reader :first_sample_at

      def initialize
        @latest_rtt = 0.0
        @smoothed_rtt = INITIAL_RTT
        @rttvar = INITIAL_RTT / 2
        @min_rtt = nil #: Float?
        @first_sample_at = nil #: Float?
      end

      # Takes the sample `latest_rtt`, of an ACK that reported `ack_delay`.
      # Once the handshake is confirmed the delay counts up to
      # `max_ack_delay` (MUST), before it in full (SHOULD), and never so far
      # as to take the sample under the minimum. The minimum ignores the
      # delay.
      def update(latest_rtt:, ack_delay:, max_ack_delay:, handshake_confirmed:, now:)
        @latest_rtt = latest_rtt
        min_rtt = @min_rtt
        unless min_rtt && @first_sample_at
          @min_rtt = @smoothed_rtt = latest_rtt
          @rttvar = latest_rtt / 2
          @first_sample_at = now
          return
        end
        min_rtt = @min_rtt = [min_rtt, latest_rtt].min
        ack_delay = [ack_delay, max_ack_delay].min if handshake_confirmed
        adjusted = latest_rtt >= min_rtt + ack_delay ? latest_rtt - ack_delay : latest_rtt
        @rttvar = 0.75 * @rttvar + 0.25 * (@smoothed_rtt - adjusted).abs
        @smoothed_rtt = 0.875 * @smoothed_rtt + 0.125 * adjusted
      end

      # The minimum taken again from the latest sample, after persistent
      # congestion (RFC 9002 "Estimating min_rtt").
      def reset_min_rtt
        @min_rtt = @latest_rtt if @first_sample_at
      end

      # The PTO period before backoff and max_ack_delay (RFC 9002 "Computing
      # PTO").
      def pto_period = @smoothed_rtt + [4 * @rttvar, GRANULARITY].max
    end
  end
end
