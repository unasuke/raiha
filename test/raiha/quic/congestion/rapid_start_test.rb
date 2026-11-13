require "test_helper"
require "raiha/quic"
require "raiha/quic/test"

# Rapid Start (draft-kazuho-ccwg-rapid-start-02) wrapping NewReno or CUBIC:
# its growth, its pacing, the first recovery period and the hand-over.
class RaihaNextQUICCongestionRapidStartTest < Minitest::Test
  include Raiha::Next::QUIC::Test::CongestionContract

  QUIC = Raiha::Next::QUIC
  RapidStart = QUIC::Congestion::Startup::RapidStart
  NewReno = QUIC::Congestion::NewReno
  Cubic = QUIC::Congestion::Cubic
  MDS = 1200
  INITIAL_WINDOW = QUIC::Config::DEFAULT_INITIAL_WINDOW
  # The BDP and queue of the path the recovery tests run on, a hundred
  # datagrams.
  FULL_BDP = 120_000

  class Recorder
    include Raiha::Next::QUIC::Tracer

    attr_reader :states

    def initialize = @states = []

    def congestion_state_updated(old:, new:, now:) = @states << [old, new]
  end

  def congestion_control = Cubic

  def rapid_start(algorithm = Cubic, initial_window: INITIAL_WINDOW, tracer: nil, **config)
    cc = algorithm.new(max_datagram_size: MDS, initial_window:, config: QUIC::Config.new(**config))
    RapidStart.new(cc, max_datagram_size: MDS, initial_window:, tracer:)
  end

  def ack(cc, bytes, sent_at:, now:, rtt: 0.05, min_rtt: 0.05, app_limited: false)
    cc.on_ack(acked_bytes: bytes, largest_acked_sent_at: sent_at, latest_rtt: rtt, smoothed_rtt: rtt, min_rtt:, app_limited:, now:)
  end

  def lose(cc, bytes, sent_at:, now:, persistent: false)
    cc.on_loss(lost_bytes: bytes, largest_lost_sent_at: sent_at, persistent:, now:)
  end

  # Rapid Start grown by three times to `growth` times FULL_BDP, its
  # recovery period begun at 2.0 by a loss, or by an ECN-CE when `ecn`, and
  # what was in flight then resolved as a tail drop would: FULL_BDP
  # acknowledged, the rest lost, in ten parts each, in `order`.
  def recovered(algorithm, growth, order: :alternate, ecn: false, **config)
    cc = rapid_start(algorithm, **config)
    before = (growth * FULL_BDP).to_i
    ack(cc, (before - cc.window) / 2, sent_at: 0.5, now: 1.0)
    assert_equal before, cc.window
    acks = [FULL_BDP / 10] * 10
    losses = [(before - FULL_BDP) / 10] * 10
    if ecn
      cc.on_ecn_ce(largest_acked_sent_at: 1.5, now: 2.0)
    else
      lose(cc, losses.shift, sent_at: 1.5, now: 2.0)
    end
    events = case order
      when :alternate then acks.zip(losses).flatten.compact.each_with_index.map { |bytes, i| [i.even? ? :ack : :loss, bytes] }
      when :loss_first then losses.map { [:loss, _1] } + acks.map { [:ack, _1] }
      when :ack_first then acks.map { [:ack, _1] } + losses.map { [:loss, _1] }
      end
    events.each_with_index do |(kind, bytes), i|
      now = 2.0 + 0.01 * (i + 1)
      kind == :ack ? ack(cc, bytes, sent_at: 1.9, now:) : lose(cc, bytes, sent_at: 1.9, now:)
    end
    cc
  end

  # The version is part of what qlog records, and the threshold that of
  # that version: min(min_rtt + 4 ms, min_rtt × 1.10).
  def test_the_draft_and_its_threshold
    assert_equal "draft-kazuho-ccwg-rapid-start-02", RapidStart::DRAFT
    assert_in_delta 0.011, RapidStart.queue_buildup_threshold(0.01), 1e-12
    assert_in_delta 0.104, RapidStart.queue_buildup_threshold(0.1), 1e-12
  end

  # Three times a round trip while rtt_floor, the least RTT of the last
  # min_rtt or so, is within the threshold, 54 ms for 50; twice once it is
  # not; three times again once a sample within it comes.
  def test_growth_by_the_queue
    cc = rapid_start
    ack(cc, 12_000, sent_at: 0.95, now: 1.0)
    assert_equal [36_000, :rapid_start], [cc.window, cc.state]
    ack(cc, 12_000, sent_at: 1.14, now: 1.2, rtt: 0.06)
    assert_equal 48_000, cc.window
    ack(cc, 12_000, sent_at: 1.16, now: 1.21)
    assert_equal 72_000, cc.window
  end

  # No pacing before an RTT sample. The first full flight after it, until
  # the bytes sent in flight since come to the window, goes over a full
  # RTT, at the window a smoothed RTT, and no faster than slow start's
  # first, twice RFC 9002's initial window: with an initial window of twenty
  # datagrams the window decides, with one of ten slow start's rate. Then
  # three times the window a smoothed RTT, or twice.
  def test_pacing
    cc = rapid_start(initial_window: ->(mds) { 20 * mds })
    cc.on_packet_sent(bytes: 1200, now: 0.9)
    assert_nil cc.pacing_rate
    ack(cc, 1200, sent_at: 0.95, now: 1.0)
    assert_in_delta 26_400 / 0.05, cc.pacing_rate
    21.times { cc.on_packet_sent(bytes: 1200, now: 1.0) }
    assert_in_delta 26_400 / 0.05, cc.pacing_rate
    cc.on_packet_sent(bytes: 1200, now: 1.0)
    assert_in_delta 3 * 26_400 / 0.05, cc.pacing_rate
    ack(cc, 1200, sent_at: 1.0, now: 1.25, rtt: 0.06)
    assert_in_delta 2 * 27_600 / 0.06, cc.pacing_rate

    cc = rapid_start
    ack(cc, 1200, sent_at: 0.95, now: 1.0)
    assert_in_delta 2 * 12_000 / 0.05, cc.pacing_rate
  end

  # An ACK without an RTT sample lets the old ones go all the same: with
  # none in the last min_rtt, the window grows as in slow start.
  def test_growth_without_a_recent_sample
    cc = rapid_start
    ack(cc, 12_000, sent_at: 0.95, now: 1.0)
    cc.on_ack(acked_bytes: 12_000, largest_acked_sent_at: 1.1, latest_rtt: nil, smoothed_rtt: 0.05, min_rtt: 0.05, app_limited: false,
      now: 1.2)
    assert_equal 48_000, cc.window
  end

  # The recovery period goes at 1.25 times the window a smoothed RTT, and
  # tells the tracer, as does the hand-over: 36,000 bytes times 9/10, less
  # 9/10 of the 1,200 lost, is 31,320.
  def test_pacing_and_state_in_recovery
    tracer = Recorder.new
    cc = rapid_start(tracer:)
    ack(cc, 12_000, sent_at: 0.95, now: 1.0)
    lose(cc, 1200, sent_at: 0.99, now: 1.1)
    assert_equal :recovery, cc.state
    assert_in_delta 1.25 * 31_320 / 0.05, cc.pacing_rate, 1
    ack(cc, 1200, sent_at: 1.2, now: 1.3)
    assert_equal [%i[rapid_start recovery], %i[recovery concave]], tracer.states
  end

  # An MTU update in the recovery period leaves the window as it is, no
  # longer the initial one, and the window no lower than the minimum for
  # the new size: 9,000 bytes lifted to 18,000, which a loss more does not
  # take below.
  def test_mtu_updated_in_recovery
    cc = rapid_start(NewReno)
    lose(cc, 1200, sent_at: 0.5, now: 1.0)
    assert_equal 9000, cc.window
    cc.on_mtu_updated(max_datagram_size: 1500, now: 1.1)
    assert_equal 9000, cc.window
    cc.on_mtu_updated(max_datagram_size: 9000, now: 1.2)
    lose(cc, 9000, sent_at: 0.6, now: 1.3)
    assert_equal 18_000, cc.window
  end

  # The window the first recovery period ends with is beta times the bytes
  # acknowledged in it, however many were lost and whatever the growth
  # before; ECN-CE marks with the Config's beta_ecn.
  def test_the_window_after_recovery
    [[NewReno, 0.5], [Cubic, 0.7]].each do |algorithm, beta|
      [1.5, 2, 3].each do |growth|
        assert_in_delta beta * FULL_BDP, recovered(algorithm, growth).window, 2, "#{algorithm} #{growth}"
      end
    end
    [0.8, 0.85].each do |beta_ecn|
      assert_in_delta beta_ecn * FULL_BDP, recovered(Cubic, 3, ecn: true, beta_ecn:).window, 2, beta_ecn.to_s
    end
  end

  # Nor does the order the ACKs and losses come in.
  def test_the_order_does_not_matter
    windows = %i[alternate loss_first ack_first].map { |order| recovered(Cubic, 2, order:).window }
    assert_equal 1, windows.uniq.size, windows.inspect
  end

  # K = 2/3 is just enough: grown by three times, with two bytes lost for
  # each acknowledged, sending starts again, the window up to the bytes in
  # flight, once 1 - beta of the BDP is acknowledged, no more drained from
  # the queue than congestion avoidance would.
  def test_the_silence
    cc = rapid_start
    ack(cc, (3 * FULL_BDP - cc.window) / 2, sent_at: 0.5, now: 1.0)
    in_flight = 3 * FULL_BDP
    lose(cc, 0, sent_at: 1.5, now: 2.0)
    acked = (1..100).find do |step|
      ack(cc, FULL_BDP / 100, sent_at: 1.9, now: 2.0 + 0.001 * step)
      lose(cc, 2 * FULL_BDP / 100, sent_at: 1.9, now: 2.0 + 0.001 * step)
      in_flight -= 3 * FULL_BDP / 100
      cc.window >= in_flight
    end
    assert_equal 30, acked
  end

  # Grown by three times, the floor, a third of beta times the window
  # before, is where the window lands: a loss more takes it no lower. Grown
  # by two, it lands above the floor, and the loss lowers it.
  def test_the_floor_is_the_landing_of_three_times
    cc = recovered(Cubic, 3)
    landing = cc.window
    lose(cc, 12_000, sent_at: 1.9, now: 2.5)
    assert_in_delta landing, cc.window, 1
    cc = recovered(Cubic, 2)
    landing = cc.window
    lose(cc, 12_000, sent_at: 1.9, now: 2.5)
    assert_operator cc.window, :<, landing
  end

  # A CE mark and no loss: the period ends with beta times the window
  # before it (Interaction with ECN).
  def test_ecn_ce_alone
    cc = rapid_start
    ack(cc, 54_000, sent_at: 0.5, now: 1.0)
    cc.on_ecn_ce(largest_acked_sent_at: 1.5, now: 2.0)
    10.times { |i| ack(cc, 12_000, sent_at: 1.9, now: 2.1 + 0.01 * i) }
    assert_in_delta 0.7 * 120_000, cc.window, 2
  end

  # The first ACK of a packet sent after the period began ends it: Rapid
  # Start is done, and the controller goes on in congestion avoidance from
  # where the window landed, that ACK its first.
  def test_the_hand_over
    { NewReno => :congestion_avoidance, Cubic => :reno_friendly }.each do |algorithm, state|
      cc = recovered(algorithm, 2)
      landing = cc.window
      refute cc.done?
      ack(cc, 12_000, sent_at: 2.5, now: 3.0)
      assert cc.done?
      controller = cc.handover
      assert_kind_of algorithm, controller
      assert_operator controller.window, :>, landing
      assert_equal [controller.window, state], [cc.window, cc.state]
      assert_equal controller.metrics, cc.metrics
    end
  end

  # A loss of a packet sent after the period began is a congestion event of
  # the controller's, after the hand-over; with no ACK, as by the loss
  # timer, the controller paces by the smoothed RTT Rapid Start had.
  def test_a_new_congestion_event_is_the_controllers
    cc = recovered(Cubic, 2)
    landing = cc.window
    lose(cc, 1200, sent_at: 2.5, now: 3.0)
    assert cc.done?
    assert_equal [(landing * 0.7).to_i, :recovery], [cc.handover.window, cc.handover.state]
    assert_in_delta 1.25 * cc.window / 0.05, cc.pacing_rate, 30
  end

  # Persistent congestion hands over at once, and the controller takes the
  # window to the minimum.
  def test_persistent_congestion_hands_over
    cc = rapid_start
    ack(cc, 12_000, sent_at: 0.95, now: 1.0)
    lose(cc, 1200, sent_at: 0.99, now: 1.1, persistent: true)
    assert cc.done?
    assert_equal cc.minimum_window, cc.handover.window
  end

  private def new_controller = rapid_start
end
