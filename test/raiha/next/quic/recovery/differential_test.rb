require "raiha/next/test_helper"
require "raiha/next/support/quic_recovery"
require "raiha/next/support/quic_recovery_reference"

# Loss recovery's design, "Testing": seeded runs of sending, ACKs, the
# handshake going on and time going by, given both to Recovery and to RFC
# 9002 Appendix A written out, and compared after every step: the packets
# newly acknowledged and lost, the probes asked for, the loss detection
# timer, the PTO count and the RTT. Left out are what Recovery does
# otherwise on purpose: what the probes carry, persistent congestion judged
# within one space (once Recovery establishes it the reference takes its
# minimum RTT again too), the lost packets kept, which come back as
# acknowledged after all, and ECN, which Appendix A has not.
class RaihaNextQUICRecoveryDifferentialTest < Minitest::Test
  include NextQUICRecovery

  Reference = NextQUICRecoveryReference
  PACKET_TYPES = { initial: :initial, handshake: :handshake, application_data: :one_rtt }.freeze
  # The spaces sent in at each stage of the handshake.
  SPACES = {
    start: %i[initial], keys: %i[initial handshake application_data],
    validated: %i[handshake application_data], confirmed: %i[application_data]
  }.freeze
  # What a packet is, as [ack_eliciting, in_flight]: mostly ack-eliciting,
  # now and then of only ACKs or of only PADDING.
  KINDS = [[true, true], [true, true], [true, true], [true, true], [false, false], [false, true]].freeze
  RUNS = 30
  STEPS = 300

  # NewReno that keeps whether persistent congestion was established.
  class Spy < QUIC::Congestion::NewReno
    attr_accessor :persistent

    def on_loss(persistent:, **)
      @persistent ||= persistent
      super
    end
  end

  def test_client = RUNS.times { |seed| play(:client, seed) }

  def test_server = RUNS.times { |seed| play(:server, seed) }

  private def play(role, seed)
    @role = role
    @rng = Random.new(seed)
    @loss_rate = @rng.rand * 0.3
    config = QUIC::Config.new(congestion_control: Spy)
    @ours = QUIC::Recovery.new(role:, config:, path: QUIC::Path.new(config:), random: Random.new(seed), now: 1.0)
    @reference = Reference.new(role:, max_ack_delay: 0.025)
    @now = 1.0
    @outage_until = 0.0
    @stage = :start
    @limited = false
    # What reached the peer in each space, as [packet number, arrival].
    @delivered = SPACES.fetch(:keys).to_h { [_1, []] }
    @lost_before = SPACES.fetch(:keys).to_h { [_1, []] }
    @log = ["#{role}, seed #{seed}"]
    STEPS.times do
      case @rng.rand
      when 0...0.4 then send_one(SPACES.fetch(@stage).sample(random: @rng)) unless @limited
      when 0.4...0.65 then acknowledge(SPACES.fetch(@stage).sample(random: @rng))
      when 0.65...0.88 then wait
      when 0.88...0.93 then go_on
      when 0.93...0.97 then limit
      else outage
      end
    end
  end

  private def send_one(space, probe: false)
    ack_eliciting, in_flight = probe ? [true, true] : KINDS.sample(random: @rng)
    type = PACKET_TYPES.fetch(space)
    number = @ours.next_packet_number(type)
    sent_bytes = @rng.rand(50..1200)
    @log << "#{@now}: send #{space} #{number} #{ack_eliciting} #{in_flight} #{sent_bytes}"
    @ours.on_packet_sent(packet_type: type, packet_number: number, sent_bytes:, ack_eliciting:, in_flight:, duties: [], now: @now)
    @reference.on_packet_sent(number, space, ack_eliciting, in_flight, sent_bytes, @now)
    @delivered.fetch(space) << [number, @now + 0.02 + @rng.rand * 0.08] if @now >= @outage_until && @rng.rand >= @loss_rate
    compare_state
  end

  # An ACK of what reached the peer 10 ms ago at least, now and then of an
  # older state.
  private def acknowledge(space)
    return if @now < @outage_until
    upto = @rng.rand < 0.8 ? @now - 0.01 : @now - 0.01 - @rng.rand * 0.2
    numbers = @delivered.fetch(space).filter_map { |number, arrival| number if arrival <= upto }.sort
    return if numbers.empty?
    ranges = numbers.slice_when { |a, b| b != a + 1 }.map { |run| run.first..run.last }.reverse
    delay = @rng.rand * 0.03
    @log << "#{@now}: ack #{space} #{ranges} #{delay}"
    ack = QUIC::Wire::Frame::Ack.new(ranges:, delay:, ecn: nil)
    compare(space, @ours.on_ack_received(packet_type: PACKET_TYPES.fetch(space), ack:, now: @now),
      @reference.on_ack_received(ranges, delay, space, @now))
  end

  # Time goes by, running out the timers on the way.
  private def wait
    target = @now + @rng.rand * 0.3
    while (timer = @ours.loss_detection_timer) && timer <= target
      @now = timer
      @log << "#{@now}: timeout"
      space = loss_space
      outcome = @ours.on_timeout(now: @now)
      compare(space, outcome, @reference.on_loss_detection_timeout(@now))
      probe(outcome.probe)
    end
    @now = target
  end

  private def probe(probe)
    probe&.packets&.times { send_one(probe.space, probe: true) }
  end

  # Nothing gets through for up to 8 s, and time goes by.
  private def outage
    @outage_until = @now + @rng.rand * 8
    @log << "#{@now}: outage until #{@outage_until}"
    wait while @now < @outage_until
  end

  # The handshake goes on: the Handshake keys, then the Initial keys
  # discarded, by when a server knows the client's address, then the
  # handshake confirmed and the Handshake keys discarded.
  private def go_on
    case @stage
    when :start
      @log << "#{@now}: Handshake keys"
      @ours.handshake_keys_installed!
      @reference.handshake_keys_installed!
      @stage = :keys
    when :keys
      lift if @limited
      @log << "#{@now}: Initial discarded"
      @ours.discard_space(:initial, now: @now)
      @reference.on_packet_number_space_discarded(:initial, @now)
      @delivered.fetch(:initial).clear
      @stage = :validated
    when :validated
      @log << "#{@now}: confirmed"
      @ours.handshake_confirmed!(now: @now)
      @reference.handshake_confirmed!
      @ours.discard_space(:handshake, now: @now)
      @reference.on_packet_number_space_discarded(:handshake, @now)
      @delivered.fetch(:handshake).clear
      @stage = :confirmed
    end
    compare_state
  end

  # A server not yet sure of the client's address sends up to its limit,
  # or a datagram lifts it.
  private def limit
    return unless @role == :server && %i[start keys].include?(@stage)
    if @limited
      lift
    else
      @log << "#{@now}: limited"
      @limited = true
      @ours.amplification_limited(true, now: @now)
      @reference.anti_amplification_limit_reached(@now)
    end
    compare_state
  end

  private def lift
    @log << "#{@now}: lifted"
    @limited = false
    @ours.amplification_limited(false, now: @now)
    space = loss_space
    result = @reference.on_datagram_received(@now)
    timer = @ours.loss_detection_timer
    outcome = timer && timer < @now ? @ours.on_timeout(now: @now) : QUIC::Recovery::Outcome::NONE
    compare(space, outcome, result)
    probe(outcome.probe)
  end

  # The space whose loss time the timer is set to, nil for a PTO.
  private def loss_space
    time, space = @reference.get_loss_time_and_space
    space unless time == 0
  end

  # The packets acknowledged and lost in `space`, nil for a PTO; the lost
  # packets acknowledged after all are left out.
  private def compare(space, outcome, result)
    lost_before = space ? @lost_before.fetch(space) : []
    acked = outcome.acked.map(&:packet_number) - lost_before
    lost = outcome.lost.map(&:packet_number)
    lost_before.concat(lost)
    agree([result.acked, result.lost, result.probe], [acked, lost, outcome.probe&.then { [_1.space, _1.packets] }])
    compare_state
  end

  private def compare_state
    if (spy = @ours.path.congestion).persistent
      spy.persistent = false
      @reference.reset_min_rtt
    end
    timer = @reference.loss_detection_timer
    rtt = @ours.path.rtt
    agree(
      [timer == Reference::INFINITE ? nil : timer, @reference.pto_count, @reference.latest_rtt, @reference.smoothed_rtt,
       @reference.rttvar, @reference.min_rtt],
      [@ours.loss_detection_timer, @ours.pto_count, rtt.latest_rtt, rtt.smoothed_rtt, rtt.rttvar, rtt.min_rtt || 0]
    )
  end

  # Floats within 1e-9 of each other agree.
  private def agree(expected, actual)
    close = expected.zip(actual).all? { |e, a| e == a || (e.is_a?(Float) && a.is_a?(Float) && (e - a).abs <= 1e-9) }
    assert close, -> { "#{@log.last(30).join("\n")}\n#{diff(expected, actual)}" }
  end
end
