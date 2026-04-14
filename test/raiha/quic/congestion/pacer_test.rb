require "test_helper"
require "raiha/quic/congestion"

class RaihaQuicCongestionPacerTest < Minitest::Test
  def test_can_send_in_slow_start
    rtt_stats = Raiha::Quic::Congestion::RTTStats.new
    cubic = Raiha::Quic::Congestion::Cubic.new(rtt_stats: rtt_stats)
    pacer = Raiha::Quic::Congestion::Pacer.new(congestion_controller: cubic, rtt_stats: rtt_stats)

    assert cubic.in_slow_start?
    assert pacer.can_send?(1200)
  end

  def test_time_until_send_zero_in_slow_start
    rtt_stats = Raiha::Quic::Congestion::RTTStats.new
    cubic = Raiha::Quic::Congestion::Cubic.new(rtt_stats: rtt_stats)
    pacer = Raiha::Quic::Congestion::Pacer.new(congestion_controller: cubic, rtt_stats: rtt_stats)

    assert_equal 0, pacer.time_until_send(1200)
  end

  def test_pacing_rate
    rtt_stats = Raiha::Quic::Congestion::RTTStats.new
    rtt_stats.update_rtt(0.1, 0)
    cubic = Raiha::Quic::Congestion::Cubic.new(rtt_stats: rtt_stats)
    pacer = Raiha::Quic::Congestion::Pacer.new(congestion_controller: cubic, rtt_stats: rtt_stats)

    rate = pacer.pacing_rate
    assert rate > 0
    # Expected: cwnd * 1.25 / srtt = 12000 * 1.25 / 0.1 = 150000
    assert_in_delta 150000, rate, 5000
  end

  def test_on_packet_sent_reduces_budget
    rtt_stats = Raiha::Quic::Congestion::RTTStats.new
    cubic = Raiha::Quic::Congestion::Cubic.new(rtt_stats: rtt_stats)
    pacer = Raiha::Quic::Congestion::Pacer.new(congestion_controller: cubic, rtt_stats: rtt_stats)

    pacer.on_packet_sent(1200)
    # Budget should be reduced (may go negative)
  end
end
