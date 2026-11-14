require "test_helper"
require "support/quic_recovery"

# RFC 9002 "Setting the Loss Detection Timer" and "On Timeout", as loss
# recovery's design, "Loss detection timer and PTO", applies them.
class RaihaQUICRecoveryTimerTest < Minitest::Test
  include QUICRecovery

  Probe = QUIC::Recovery::Probe
  # The first PTO period: 0.333 + 4 * 0.1665.
  PTO = 0.999

  def test_pto_after_sending
    recovery = recovery(role: :server)
    assert_nil recovery.next_timeout
    send_packet(recovery, :initial, now: 1.0)
    assert_in_delta 1.0 + PTO, recovery.next_timeout
    send_packet(recovery, :initial, now: 1.5)
    assert_in_delta 1.5 + PTO, recovery.next_timeout
  end

  # Two probes in the space whose PTO ran out, nothing declared lost, and
  # the next PTO twice as far.
  def test_pto_fires
    recovery = recovery(role: :server)
    send_packet(recovery, :initial, now: 1.0)
    assert_same QUIC::Recovery::Outcome::NONE, recovery.on_timeout(now: 1.5)
    outcome = recovery.on_timeout(now: 2.0)
    assert_equal Probe.new(space: :initial, packets: 2), outcome.probe
    assert_empty outcome.lost
    assert_equal [1, 1200], [recovery.pto_count, recovery.path.bytes_in_flight]
    assert_in_delta 1.0 + 2 * PTO, recovery.next_timeout
    recovery.on_timeout(now: 3.0)
    assert_in_delta 1.0 + 4 * PTO, recovery.next_timeout
  end

  # An ACK takes the count back to 0.
  def test_an_ack_resets_the_backoff
    recovery = recovery(role: :server)
    send_packet(recovery, :handshake, now: 0.0)
    send_packet(recovery, :handshake, now: 0.0)
    recovery.on_timeout(now: 1.0)
    recovery.on_ack_received(packet_type: :handshake, ack: ack(0..0), now: 1.5)
    assert_equal 0, recovery.pto_count
  end

  # A client not yet known to the server keeps its backoff.
  def test_a_client_keeps_the_backoff_until_its_address_is_validated
    recovery = recovery(role: :client)
    send_packet(recovery, :initial, now: 0.0)
    send_packet(recovery, :initial, now: 0.0)
    recovery.on_timeout(now: 1.0)
    recovery.on_ack_received(packet_type: :initial, ack: ack(0..0), now: 1.5)
    assert_equal 1, recovery.pto_count
  end

  # The time threshold comes first and declares losses without backoff.
  def test_loss_time_comes_first
    recovery = recovery(role: :server)
    send_packet(recovery, :handshake, now: 1.0)
    send_packet(recovery, :handshake, now: 1.0)
    recovery.on_ack_received(packet_type: :handshake, ack: ack(1..1), now: 1.05)
    assert_in_delta 1.0 + 1.125 * 0.05, recovery.next_timeout
    outcome = recovery.on_timeout(now: 1.06)
    assert_equal [[0], nil, 0], [outcome.lost.map(&:packet_number), outcome.probe, recovery.pto_count]
    assert_nil recovery.next_timeout
  end

  # Run out at the loss time itself, the packet is lost, though here the
  # loss time less the loss delay rounds under 0.5, the time it was sent.
  def test_lost_at_the_loss_time_itself
    recovery = recovery(role: :server)
    send_packet(recovery, :handshake, now: 0.5)
    send_packet(recovery, :handshake, now: 0.5)
    recovery.on_ack_received(packet_type: :handshake, ack: ack(1..1), now: 0.6)
    outcome = recovery.on_timeout(now: recovery.loss_detection_timer)
    assert_equal [0], outcome.lost.map(&:packet_number)
    assert_nil recovery.loss_detection_timer
  end

  # Application Data counts once the handshake is confirmed, with the
  # peer's max_ack_delay.
  def test_application_data
    recovery = recovery(role: :server)
    send_packet(recovery, :one_rtt, now: 1.0)
    assert_nil recovery.next_timeout
    recovery.peer_max_ack_delay = 0.1
    recovery.handshake_confirmed!(now: 1.2)
    assert_in_delta 1.0 + PTO + 0.1, recovery.next_timeout
    assert_equal Probe.new(space: :application_data, packets: 2), recovery.on_timeout(now: 2.5).probe
    assert_in_delta 1.0 + 2 * (PTO + 0.1), recovery.next_timeout
  end

  # The earliest of the spaces.
  def test_earliest_space
    recovery = recovery(role: :server)
    send_packet(recovery, :handshake, now: 0.5)
    send_packet(recovery, :initial, now: 0.6)
    assert_in_delta 0.5 + PTO, recovery.next_timeout
    assert_equal :handshake, recovery.on_timeout(now: 2.0).probe.space
  end

  # RFC 9002 "Handling Anti-Amplification Limits".
  def test_amplification_limit
    recovery = recovery(role: :server)
    send_packet(recovery, :initial, now: 0.0)
    recovery.amplification_limited(true, now: 0.1)
    assert_nil recovery.next_timeout
    recovery.amplification_limited(false, now: 3.0)
    assert_in_delta PTO, recovery.next_timeout
    assert recovery.on_timeout(now: 3.0).probe
  end

  # RFC 9002 "Handshakes and New Paths": with nothing in flight a client
  # not yet known to the server sends one packet a PTO from now, in a
  # Handshake packet once it has the keys.
  def test_a_client_avoids_a_deadlock
    recovery = recovery(role: :client)
    send_packet(recovery, :initial, now: 0.0)
    recovery.on_ack_received(packet_type: :initial, ack: ack(0..0), now: 0.1)
    assert_in_delta 0.1 + 0.1 + 4 * 0.05, recovery.next_timeout
    assert_equal Probe.new(space: :initial, packets: 1), recovery.on_timeout(now: 1.0).probe
    recovery.handshake_keys_installed!
    assert_equal Probe.new(space: :handshake, packets: 1), recovery.on_timeout(now: 5.0).probe
    server = recovery(role: :server)
    send_packet(server, :initial, now: 0.0)
    server.on_ack_received(packet_type: :initial, ack: ack(0..0), now: 0.1)
    assert_nil server.next_timeout
  end

  # Loss recovery's design, "Tracer": the timer set, run out and cancelled.
  def test_timer_events
    tracer = RecordingTracer.new
    recovery = recovery(role: :server, tracer:)
    send_packet(recovery, :initial, now: 1.0)
    recovery.on_timeout(now: 2.0)
    recovery.on_ack_received(packet_type: :initial, ack: ack(0..0), now: 2.5)
    events = tracer.of(:timer_updated)
    assert_equal [%i[set initial], %i[expired initial], %i[set initial], %i[cancelled]], events.map { _1.values_at(:event_type, :space).compact }
    assert_in_delta PTO, events.first[:delta]
  end
end
