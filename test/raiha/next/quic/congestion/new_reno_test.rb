require "raiha/next/test_helper"
require "raiha/next/quic"

class RaihaNextQUICCongestionNewRenoTest < Minitest::Test
  NewReno = Raiha::Next::QUIC::Congestion::NewReno
  MDS = 1200
  # RFC 9002 "Initial and Minimum Congestion Window".
  INITIAL_WINDOW = ->(mds) { [10 * mds, [14_720, 2 * mds].max].min }

  class Recorder
    include Raiha::Next::QUIC::Tracer

    attr_reader :states

    def initialize = @states = []

    def congestion_state_updated(old:, new:, now:) = @states << [old, new]
  end

  def new_reno(tracer: nil, **config)
    NewReno.new(max_datagram_size: MDS, initial_window: INITIAL_WINDOW, config: Raiha::Next::QUIC::Config.new(**config), tracer:)
  end

  def ack(cc, bytes, sent_at:, now:, app_limited: false)
    cc.on_ack(acked_bytes: bytes, largest_acked_sent_at: sent_at, latest_rtt: 0.1, smoothed_rtt: 0.1, min_rtt: 0.1, app_limited:, now:)
  end

  def lose(cc, sent_at:, now:, persistent: false)
    cc.on_loss(lost_bytes: MDS, largest_lost_sent_at: sent_at, persistent:, now:)
  end

  # What a startup asks of the controller it wraps: beta, half or the
  # Config's beta_ecn for an ECN-CE; and the hand-over, after which the
  # window goes on in congestion avoidance, and a loss of a packet sent
  # before the recovery period it ended began is no new congestion event.
  def test_startup_exit
    cc = new_reno(beta_ecn: 0.8)
    assert_equal [0.5, 0.8, 0.5], [cc.beta(ecn: false), cc.beta(ecn: true), new_reno.beta(ecn: true)]
    cc.on_startup_exit(window: 60_000, full_bdp: 120_000.0, recovery_start: 1.0, now: 1.5)
    assert_equal [60_000, :congestion_avoidance], [cc.window, cc.state]
    lose(cc, sent_at: 0.9, now: 1.6)
    assert_equal 60_000, cc.window
    ack(cc, 6000, sent_at: 1.2, now: 1.7)
    assert_equal 60_000 + MDS * 6000 / 60_000, cc.window
  end

  def test_initial_and_minimum_windows
    cc = new_reno
    assert_equal [12_000, 2400], [cc.window, cc.minimum_window]
    assert_equal :slow_start, cc.state
    assert_equal({ congestion_window: 12_000 }, cc.metrics)
    assert_nil cc.pacing_rate
    refute NewReno.requires_rate_sample?
  end

  # Slow start adds the bytes acknowledged; congestion avoidance one
  # datagram a window.
  def test_growth
    cc = new_reno
    ack(cc, 2400, sent_at: 0.0, now: 0.1)
    assert_equal 14_400, cc.window
    lose(cc, sent_at: 0.05, now: 0.2)
    ack(cc, 7200, sent_at: 0.3, now: 0.4)
    assert_equal [7200 + MDS * 7200 / 7200, :congestion_avoidance], [cc.window, cc.state]
  end

  # RFC 9002 appendix B: a congestion event halves the window, once a
  # recovery period, and acknowledgments of packets sent before the period
  # began do not grow it.
  def test_recovery_period
    cc = new_reno
    lose(cc, sent_at: 1.0, now: 2.0)
    assert_equal [6000, :recovery], [cc.window, cc.state]
    assert_equal({ congestion_window: 6000, ssthresh: 6000 }, cc.metrics)
    lose(cc, sent_at: 1.5, now: 2.1)
    assert_equal 6000, cc.window
    ack(cc, 1200, sent_at: 2.0, now: 2.2)
    assert_equal [6000, :recovery], [cc.window, cc.state]
    ack(cc, 1200, sent_at: 2.05, now: 2.3)
    assert_equal [6240, :congestion_avoidance], [cc.window, cc.state]
    lose(cc, sent_at: 2.1, now: 2.4)
    assert_equal [3120, :recovery], [cc.window, cc.state]
  end

  def test_the_window_stays_above_the_minimum
    cc = new_reno
    5.times { |i| lose(cc, sent_at: i.to_f, now: i + 0.5) }
    assert_equal 2400, cc.window
  end

  # RFC 9002 "Persistent Congestion": the minimum, even within a recovery
  # period, then slow start again.
  def test_persistent_congestion
    cc = new_reno
    lose(cc, sent_at: 1.0, now: 2.0)
    lose(cc, sent_at: 1.5, now: 2.1, persistent: true)
    assert_equal [2400, :slow_start], [cc.window, cc.state]
    ack(cc, 1200, sent_at: 1.8, now: 2.2)
    assert_equal 3600, cc.window
  end

  def test_ecn_ce_is_a_congestion_event
    cc = new_reno
    cc.on_ecn_ce(largest_acked_sent_at: 1.0, now: 2.0)
    assert_equal [6000, :recovery], [cc.window, cc.state]
    cc.on_ecn_ce(largest_acked_sent_at: 1.9, now: 2.1)
    assert_equal 6000, cc.window
  end

  # With beta_ecn, an ECN-CE alone shrinks the window by it; a loss still
  # halves it.
  def test_ecn_ce_with_beta_ecn
    cc = new_reno(beta_ecn: 0.8)
    cc.on_ecn_ce(largest_acked_sent_at: 1.0, now: 2.0)
    assert_equal 9600, cc.window
    assert_equal 9600, cc.metrics[:ssthresh]
    lost = new_reno(beta_ecn: 0.8)
    lose(lost, sent_at: 1.0, now: 2.0)
    assert_equal 6000, lost.window
  end

  # RFC 9002 "Underutilizing the Congestion Window".
  def test_application_limited
    cc = new_reno
    ack(cc, 2400, sent_at: 0.0, now: 0.1, app_limited: true)
    assert_equal [12_000, :application_limited], [cc.window, cc.state]
    ack(cc, 2400, sent_at: 0.1, now: 0.2)
    assert_equal [14_400, :slow_start], [cc.window, cc.state]
  end

  def test_mtu_updated
    cc = new_reno
    cc.on_mtu_updated(max_datagram_size: 1400, now: 0.0)
    assert_equal [14_000, 2800], [cc.window, cc.minimum_window]
    ack(cc, 1400, sent_at: 0.0, now: 0.1)
    cc.on_mtu_updated(max_datagram_size: 1500, now: 0.2)
    assert_equal [15_400, 3000], [cc.window, cc.minimum_window]
    5.times { |i| lose(cc, sent_at: i + 1.0, now: i + 1.5) }
    cc.on_mtu_updated(max_datagram_size: 9000, now: 9.0)
    assert_equal 18_000, cc.window
  end

  def test_state_changes_are_traced
    tracer = Recorder.new
    cc = new_reno(tracer:)
    lose(cc, sent_at: 1.0, now: 2.0)
    ack(cc, 1200, sent_at: 2.5, now: 3.0)
    ack(cc, 1200, sent_at: 3.0, now: 3.5, app_limited: true)
    assert_equal [%i[slow_start recovery], %i[recovery congestion_avoidance], %i[congestion_avoidance application_limited]], tracer.states
  end

  # RFC 9002 "Pacing": twice the window over the smoothed RTT in slow
  # start, 1.25 times after, and none before an RTT sample; qlog has the
  # rate in bits a second.
  def test_pacing_rate
    cc = new_reno
    cc.on_ack(acked_bytes: MDS, largest_acked_sent_at: 0.0, latest_rtt: nil, smoothed_rtt: 0.333, min_rtt: nil, app_limited: false, now: 0.1)
    assert_nil cc.pacing_rate
    refute cc.metrics.key?(:pacing_rate)
    ack(cc, MDS, sent_at: 0.0, now: 0.2)
    assert_in_delta 2.0 * cc.window / 0.1, cc.pacing_rate
    assert_equal (cc.pacing_rate * 8).to_i, cc.metrics[:pacing_rate]
    lose(cc, sent_at: 0.1, now: 0.3)
    assert_in_delta 1.25 * cc.window / 0.1, cc.pacing_rate
    # A path with no delay paces nothing.
    cc.on_ack(acked_bytes: MDS, largest_acked_sent_at: 0.4, latest_rtt: 0.0, smoothed_rtt: 0.0, min_rtt: 0.0, app_limited: false, now: 0.4)
    assert_nil cc.pacing_rate
  end
end
