require "test_helper"
require "raiha/quic/congestion/rtt_stats"

class RaihaQuicCongestionRTTStatsTest < Minitest::Test
  def test_initial_values
    stats = Raiha::Quic::Congestion::RTTStats.new
    assert_equal Float::INFINITY, stats.min_rtt
    assert_in_delta 0.333, stats.smoothed_rtt, 0.001
    refute stats.has_samples?
  end

  def test_first_sample
    stats = Raiha::Quic::Congestion::RTTStats.new
    stats.update_rtt(0.1, 0)

    assert stats.has_samples?
    assert_in_delta 0.1, stats.smoothed_rtt, 0.001
    assert_in_delta 0.05, stats.rtt_var, 0.001
    assert_in_delta 0.1, stats.min_rtt, 0.001
    assert_in_delta 0.1, stats.latest_rtt, 0.001
  end

  def test_subsequent_samples
    stats = Raiha::Quic::Congestion::RTTStats.new
    stats.update_rtt(0.1, 0)
    stats.update_rtt(0.12, 0)

    assert stats.smoothed_rtt > 0.1
    assert stats.smoothed_rtt < 0.12
    assert_in_delta 0.1, stats.min_rtt, 0.001
  end

  def test_ack_delay_adjustment
    stats = Raiha::Quic::Congestion::RTTStats.new
    stats.update_rtt(0.1, 0)
    stats.update_rtt(0.15, 0.03)

    # Adjusted RTT should be 0.15 - 0.03 = 0.12 since min_rtt + ack_delay < latest_rtt
    assert stats.smoothed_rtt < 0.15
  end

  def test_pto
    stats = Raiha::Quic::Congestion::RTTStats.new
    stats.update_rtt(0.1, 0)

    pto = stats.pto
    assert pto > 0.1 # smoothed_rtt + rtt_var + max_ack_delay
  end

  def test_loss_delay
    stats = Raiha::Quic::Congestion::RTTStats.new
    stats.update_rtt(0.1, 0)

    delay = stats.loss_delay
    assert delay >= 0.001 # at least 1ms granularity
    assert_in_delta 0.1 * 9.0 / 8.0, delay, 0.02
  end

  def test_reset
    stats = Raiha::Quic::Congestion::RTTStats.new
    stats.update_rtt(0.1, 0)
    assert stats.has_samples?

    stats.reset
    refute stats.has_samples?
    assert_equal Float::INFINITY, stats.min_rtt
  end
end
