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

  # What a startup asks of the controller it wraps: β_cubic, or the
  # Config's beta_ecn for an ECN-CE; and the hand-over. W_max is twice the
  # BDP the startup came to, 240,000 bytes for 120,000: K is 6.9 s from a
  # window of 84,000, and four seconds of a window acknowledged each round
  # trip take the window to 228,000 or so, where W_max of the BDP alone
  # would have stopped it at 120,000. A loss of a packet sent before the
  # recovery period began is no new congestion event.
  def test_startup_exit
    cc = cubic(beta_ecn: 0.85)
    assert_equal [0.7, 0.85, 0.7], [cc.beta(ecn: false), cc.beta(ecn: true), cubic.beta(ecn: true)]
    cc.on_startup_exit(window: 84_000, full_bdp: 120_000.0, recovery_start: 1.0, smoothed_rtt: 0.05, now: 1.5)
    assert_equal [84_000, 84_000, :concave], [cc.window, cc.metrics[:ssthresh], cc.state]
    assert_in_delta 1.25 * 84_000 / 0.05, cc.pacing_rate
    lose(cc, sent_at: 0.9, now: 1.6)
    assert_equal 84_000, cc.window
    40.times { |round| ack(cc, cc.window, sent_at: 1.6 + 0.1 * round, now: 1.7 + 0.1 * round) }
    assert_in_delta 228_000, cc.window, 5000
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

  # A controller whose window has grown to `segments` in slow start and
  # was then cut by a loss at 2.0 s.
  def after_a_loss(segments, **config)
    cc = cubic(**config)
    ack(cc, segments * MDS - cc.window, sent_at: 0.0, now: 1.0)
    lose(cc, sent_at: 1.9, now: 2.0)
    cc
  end

  # One ACK frame of a whole window every `rtt` from `from` until `to`: the
  # time, window and state after each.
  def round_trips(cc, from:, to:, rtt: 0.1, app_limited: false)
    trace = [] #: Array[[Float, Integer, Symbol]]
    now = from
    while now < to - 1e-9
      now += rtt
      ack(cc, cc.window, sent_at: now - rtt / 2, now:, smoothed_rtt: rtt, app_limited:)
      trace << [now, cc.window, cc.state]
    end
    trace
  end

  # From 70 segments after a loss at 100, the window rises fast and slows
  # towards W_max (concave), and past it speeds up again (convex), at about
  # K = cbrt(30 / C) = 4.22 s after the stage began. The first ACK of the
  # stage, where W_cubic(0) is the window itself, is W_est's; later on, AIMD
  # outgrows the cubic function again.
  def test_from_concave_to_convex
    cc = after_a_loss(100)
    trace = round_trips(cc, from: 2.0, to: 7.5).drop_while { |_, _, state| state == :reno_friendly }
    assert_equal %i[concave convex], trace.map(&:last).chunk_while { _1 == _2 }.map(&:first)
    convex_at, window, = trace.find { |_, _, state| state == :convex }
    assert_operator window, :>=, 100 * MDS
    assert_in_delta 2.0 + 4.22, convex_at, 0.25
    steps = trace.each_cons(2).map { |(_, a, _), (_, b, _)| b - a }
    concave = steps.first(trace.index { |_, _, state| state == :convex } - 1)
    assert_operator concave.first, :>, concave.last
    assert_operator steps.last, :>, steps[trace.index { |_, _, state| state == :convex }]
  end

  # RFC 9438 "Fast Convergence": a second reduction below W_max lowers
  # W_max to 0.85 of the window, so the window levels off lower than it
  # would without.
  def test_fast_convergence
    windows = [true, false].map do |fast_convergence|
      cc = after_a_loss(100, fast_convergence:)
      round_trips(cc, from: 2.0, to: 2.5)
      lose(cc, sent_at: 2.45, now: 2.5)
      round_trips(cc, from: 2.5, to: 5.0).last[1]
    end
    assert_operator windows[0], :<, windows[1]
  end

  # With a small window and a short round trip, AIMD grows faster than the
  # cubic function: the window follows W_est by 0.53 segments a round trip,
  # then by one once W_est reaches the window before the loss (RFC 9438
  # "Reno-Friendly Region").
  def test_reno_friendly_region
    cc = after_a_loss(10)
    trace = round_trips(cc, from: 2.0, to: 2.3, rtt: 0.01)
    assert trace.all? { |_, _, state| state == :reno_friendly }, trace.map(&:last).inspect
    steps = trace.each_cons(2).map { |(_, a, _), (_, b, _)| b - a }
    assert_in_delta 0.529 * MDS, steps.first, 2
    assert_in_delta MDS, steps.last, 2
  end

  # The time of the stage stands still while the connection sends nothing:
  # after twenty seconds idle, the window goes on from where it was, where
  # without the pause it would have jumped by half, as far as one ACK frame
  # takes it (RFC 9438 "Window Increase Function").
  def test_no_jump_after_an_idle_period
    paused = after_a_loss(100)
    before = round_trips(paused, from: 2.0, to: 3.0).last[1]
    ack(paused, MDS, sent_at: 3.05, now: 3.1, app_limited: true)
    after = round_trips(paused, from: 23.0, to: 23.1).last[1]
    assert_operator after, :<, before * 1.1
    jumped = after_a_loss(100)
    round_trips(jumped, from: 2.0, to: 3.0)
    assert_operator round_trips(jumped, from: 23.0, to: 23.1).last[1], :>=, before * 1.4
  end

  # RFC 9002 "Pacing": twice the window over the smoothed RTT in slow
  # start, 1.25 times after, and none before an RTT sample; qlog has the
  # rate in bits a second.
  def test_pacing_rate
    cc = cubic
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
