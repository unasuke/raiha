# frozen_string_literal: true

module Raiha::Next::QUIC
  module Congestion
    # The rate a window is paced at (RFC 9002 "Pacing"): N times the window
    # over the smoothed RTT, N small but above 1 so that variations in RTT
    # do not leave the window unused. Slow start paces at twice that, as the
    # window doubles in a round trip and the rate is to keep up with it
    # (Linux's pacing_ss_ratio, quicly's slow start).
    module Pacing
      SLOW_START = 2.0
      OTHERWISE = 1.25

      # Bytes a second; nil for an RTT of nothing, a path with no delay,
      # where there is nothing to pace.
      def self.rate(window, smoothed_rtt, slow_start:)
        (slow_start ? SLOW_START : OTHERWISE) * window / smoothed_rtt if smoothed_rtt.positive?
      end
    end
  end
end
