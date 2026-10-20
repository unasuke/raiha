require "raiha/next/test_helper"
require "raiha/next/quic"
require "raiha/next/quic/test"

class RaihaNextQUICCongestionCubicTest < Minitest::Test
  include Raiha::Next::QUIC::Test::CongestionContract

  Cubic = Raiha::Next::QUIC::Congestion::Cubic
  MDS = 1200
  INITIAL_WINDOW = Raiha::Next::QUIC::Config::DEFAULT_INITIAL_WINDOW

  def congestion_control = Cubic

  def cubic(**config) = Cubic.new(max_datagram_size: MDS, initial_window: INITIAL_WINDOW, config: Raiha::Next::QUIC::Config.new(**config))

  def ack(cc, bytes, sent_at:, now:, app_limited: false, smoothed_rtt: 0.1)
    cc.on_ack(acked_bytes: bytes, largest_acked_sent_at: sent_at, latest_rtt: smoothed_rtt, smoothed_rtt:, min_rtt: smoothed_rtt,
      app_limited:, now:)
  end

  def lose(cc, sent_at:, now:, persistent: false)
    cc.on_loss(lost_bytes: MDS, largest_lost_sent_at: sent_at, persistent:, now:)
  end

  def test_slow_start_grows_by_the_bytes_acknowledged
    cc = cubic
    assert_equal [12_000, :slow_start], [cc.window, cc.state]
    ack(cc, 2400, sent_at: 0.0, now: 0.1)
    assert_equal 14_400, cc.window
  end

  # RFC 9438 "Multiplicative Decrease": 0.7 of the window, once a round
  # trip.
  def test_a_loss_takes_the_window_to_seven_tenths
    cc = cubic
    lose(cc, sent_at: 1.0, now: 2.0)
    assert_equal [8400, :recovery], [cc.window, cc.state]
    assert_equal 8400, cc.metrics[:ssthresh]
    lose(cc, sent_at: 1.9, now: 2.1)
    assert_equal 8400, cc.window
  end

  def test_ecn_ce_with_and_without_beta_ecn
    cc = cubic
    cc.on_ecn_ce(largest_acked_sent_at: 1.0, now: 2.0)
    assert_equal 8400, cc.window
    cc = cubic(beta_ecn: 0.85)
    cc.on_ecn_ce(largest_acked_sent_at: 1.0, now: 2.0)
    assert_equal 10_200, cc.window
  end

  # The recovery period ends with an ACK of a packet sent after it began,
  # and the window grows in congestion avoidance from then on.
  def test_congestion_avoidance_after_recovery
    cc = cubic
    lose(cc, sent_at: 1.0, now: 2.0)
    ack(cc, MDS, sent_at: 1.5, now: 2.1)
    assert_equal 8400, cc.window
    ack(cc, MDS, sent_at: 2.05, now: 2.2)
    assert_operator cc.window, :>, 8400
    refute_includes %i[recovery slow_start], cc.state
  end

  # Persistent congestion: the minimum window and slow start up to the
  # threshold the congestion event set.
  def test_persistent_congestion
    cc = cubic
    lose(cc, sent_at: 1.0, now: 2.0, persistent: true)
    assert_equal [2 * MDS, :slow_start], [cc.window, cc.state]
    ack(cc, 2 * MDS, sent_at: 2.1, now: 2.2)
    assert_equal 4 * MDS, cc.window
  end

  def test_application_limited_holds_the_window
    cc = cubic
    ack(cc, 2400, sent_at: 0.0, now: 0.1, app_limited: true)
    assert_equal [12_000, :application_limited], [cc.window, cc.state]
  end

  def test_the_constants
    assert_in_delta 0.529, Cubic::ALPHA, 0.001
    assert_same Cubic, Raiha::Next::QUIC::Congestion.resolve(:cubic)
  end
end
