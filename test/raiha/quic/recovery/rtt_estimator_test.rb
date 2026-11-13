require "test_helper"
require "raiha/quic"

class RaihaNextQUICRecoveryRttEstimatorTest < Minitest::Test
  RttEstimator = Raiha::QUIC::Recovery::RttEstimator

  def sample(rtt, latest, ack_delay: 0.0, max_ack_delay: 0.025, confirmed: true, now: 1.0)
    rtt.update(latest_rtt: latest, ack_delay:, max_ack_delay:, handshake_confirmed: confirmed, now:)
  end

  # RFC 9002 "Initial RTT": the first PTO is about a second.
  def test_before_a_sample
    rtt = RttEstimator.new
    assert_equal [0.0, 0.333, 0.1665, nil, nil], [rtt.latest_rtt, rtt.smoothed_rtt, rtt.rttvar, rtt.min_rtt, rtt.first_sample_at]
    assert_in_delta 0.999, rtt.pto_period
  end

  def test_the_first_sample_replaces_the_initial_values
    rtt = RttEstimator.new
    sample(rtt, 0.1, ack_delay: 0.02, now: 2.0)
    assert_equal [0.1, 0.1, 0.05, 0.1, 2.0], [rtt.latest_rtt, rtt.smoothed_rtt, rtt.rttvar, rtt.min_rtt, rtt.first_sample_at]
  end

  # RFC 9002 "Estimating smoothed_rtt and rttvar".
  def test_later_samples_take_off_the_ack_delay
    rtt = RttEstimator.new
    sample(rtt, 0.1)
    sample(rtt, 0.14, ack_delay: 0.02)
    assert_in_delta 0.75 * 0.05 + 0.25 * (0.1 - 0.12).abs, rtt.rttvar
    assert_in_delta 0.875 * 0.1 + 0.125 * 0.12, rtt.smoothed_rtt
    assert_equal 0.1, rtt.min_rtt
  end

  # Once the handshake is confirmed the delay counts up to max_ack_delay;
  # before it, in full.
  def test_max_ack_delay
    confirmed = RttEstimator.new
    sample(confirmed, 0.1)
    sample(confirmed, 0.2, ack_delay: 0.05, max_ack_delay: 0.025)
    assert_in_delta 0.875 * 0.1 + 0.125 * 0.175, confirmed.smoothed_rtt
    unconfirmed = RttEstimator.new
    sample(unconfirmed, 0.1, confirmed: false)
    sample(unconfirmed, 0.2, ack_delay: 0.05, max_ack_delay: 0.025, confirmed: false)
    assert_in_delta 0.875 * 0.1 + 0.125 * 0.15, unconfirmed.smoothed_rtt
  end

  # A delay that would take the sample under the minimum is not taken off
  # (MUST NOT), and the minimum never counts it.
  def test_the_delay_does_not_take_the_sample_under_the_minimum
    rtt = RttEstimator.new
    sample(rtt, 0.1)
    sample(rtt, 0.11, ack_delay: 0.02)
    assert_in_delta 0.875 * 0.1 + 0.125 * 0.11, rtt.smoothed_rtt
    sample(rtt, 0.08, ack_delay: 0.02)
    assert_equal 0.08, rtt.min_rtt
  end

  # RFC 9002 "Estimating min_rtt": taken again after persistent congestion.
  def test_reset_min_rtt
    rtt = RttEstimator.new
    rtt.reset_min_rtt
    assert_nil rtt.min_rtt
    sample(rtt, 0.05)
    sample(rtt, 0.2)
    assert_equal 0.05, rtt.min_rtt
    rtt.reset_min_rtt
    assert_equal 0.2, rtt.min_rtt
  end

  def test_pto_period_has_a_floor
    rtt = RttEstimator.new
    sample(rtt, 0.0001)
    assert_in_delta 0.0001 + 0.001, rtt.pto_period
  end
end
