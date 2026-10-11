# frozen_string_literal: true

module Raiha::Next::QUIC
  # Loss recovery (RFC 9002): what was sent in each packet number space,
  # what the peer acknowledged, what is lost and when to probe, and what to
  # acknowledge in turn. The RTT, the congestion controller and the bytes in
  # flight are each path's (Path).
  class Recovery
    # kInitialRtt, the RTT before a sample (RFC 9002 "Initial RTT"). A
    # constant, and the RTT of an earlier connection is not used.
    INITIAL_RTT = 0.333
    # kGranularity, the timer granularity (RFC 9002 "Time Threshold").
    GRANULARITY = 0.001
  end
end

require_relative "recovery/rtt_estimator"
