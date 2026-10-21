require "raiha/next/test_helper"
require "raiha/next/support/quic_recovery"

# RFC 9000 "Sending ACK Frames", as loss recovery's design, "When to send an
# ACK" and "When only ACKs go", applies it.
class RaihaNextQUICRecoveryAckSendingTest < Minitest::Test
  include NextQUICRecovery

  def receive(recovery, packet_type, number, now:, ack_eliciting: true, ecn: :not_ect, received_at: now)
    recovery.on_packet_received(packet_type:, packet_number: number, ecn:, ack_eliciting:, now:, received_at:)
  end

  # Initial and Handshake packets are acknowledged at once (MUST).
  def test_initial_and_handshake_at_once
    recovery = recovery()
    receive(recovery, :initial, 0, now: 1.0)
    assert recovery.ack_due?(:initial, now: 1.0)
    receive(recovery, :handshake, 0, now: 1.0)
    assert recovery.ack_due?(:handshake, now: 1.0)
    assert_equal 1.0, recovery.next_timeout
  end

  # One 1-RTT packet waits up to max_ack_delay; the second goes at once.
  def test_application_data
    recovery = recovery(config: QUIC::Config.new(max_ack_delay: 0.02))
    receive(recovery, :one_rtt, 0, now: 1.0)
    refute recovery.ack_due?(:application_data, now: 1.0)
    assert recovery.ack_owed?(:application_data)
    assert_in_delta 1.02, recovery.next_timeout
    assert recovery.ack_due?(:application_data, now: 1.02)
    receive(recovery, :one_rtt, 1, now: 1.01)
    assert recovery.ack_due?(:application_data, now: 1.01)
  end

  # Out of order or after a gap, at once (SHOULD); a packet that elicits no
  # ACK owes none (MUST NOT answer it alone).
  def test_reordering_and_gaps
    gap = recovery()
    receive(gap, :one_rtt, 0, now: 1.0)
    gap.on_ack_sent(:application_data, now: 1.0)
    receive(gap, :one_rtt, 2, now: 1.1)
    assert gap.ack_due?(:application_data, now: 1.1)
    reordered = recovery()
    receive(reordered, :one_rtt, 3, now: 1.0)
    reordered.on_ack_sent(:application_data, now: 1.0)
    receive(reordered, :one_rtt, 1, now: 1.1)
    assert reordered.ack_due?(:application_data, now: 1.1)
    quiet = recovery()
    receive(quiet, :one_rtt, 0, now: 1.0, ack_eliciting: false)
    receive(quiet, :one_rtt, 5, now: 1.0, ack_eliciting: false)
    refute quiet.ack_owed?(:application_data)
    assert_nil quiet.next_timeout
  end

  # A gap below non-ack-eliciting packets received is no gap.
  def test_no_gap_through_packets_received
    recovery = recovery()
    receive(recovery, :one_rtt, 0, now: 1.0)
    recovery.on_ack_sent(:application_data, now: 1.0)
    receive(recovery, :one_rtt, 1, now: 1.0, ack_eliciting: false)
    receive(recovery, :one_rtt, 2, now: 1.1)
    refute recovery.ack_due?(:application_data, now: 1.1)
  end

  def test_ce_marks_at_once
    recovery = recovery()
    receive(recovery, :one_rtt, 0, now: 1.0, ecn: :ce)
    assert recovery.ack_due?(:application_data, now: 1.0)
  end

  # The frame: the ranges, the delay since the largest came (counting the
  # wait for keys), and the ECN counts once a packet was marked.
  def test_the_ack_frame
    recovery = recovery()
    assert_nil recovery.ack_frame(:application_data, now: 1.0)
    receive(recovery, :one_rtt, 0, now: 1.0)
    receive(recovery, :one_rtt, 2, now: 1.2, received_at: 1.1)
    frame = recovery.ack_frame(:application_data, now: 1.25)
    assert_equal [2..2, 0..0], frame.ranges
    assert_in_delta 0.15, frame.delay
    assert_nil frame.ecn
    receive(recovery, :one_rtt, 3, now: 1.3, ecn: :ect0)
    assert_equal QUIC::Wire::Frame::Ack::ECNCounts.new(ect0: 1, ect1: 0, ce: 0), recovery.ack_frame(:application_data, now: 1.3).ecn
  end

  def test_an_ack_sent_clears_the_debt
    tracer = RecordingTracer.new
    recovery = recovery(tracer:)
    receive(recovery, :one_rtt, 0, now: 1.0)
    recovery.on_ack_sent(:application_data, now: 1.01)
    refute recovery.ack_owed?(:application_data)
    assert_nil recovery.next_timeout
    assert_equal [%i[ack set], %i[ack cancelled]], tracer.of(:timer_updated).map { _1.values_at(:timer_type, :event_type) }
  end

  # RFC 9000 "Limiting Ranges by Tracking ACK Frames": with only ACKs going
  # one after another for a round trip, a PING goes along; not with the
  # first after an ack-eliciting packet.
  def test_a_ping_with_acks
    recovery = recovery()
    refute recovery.ping_with_ack?(:application_data, now: 0.0)
    send_packet(recovery, :one_rtt, now: 0.0, ack_eliciting: false, in_flight: false)
    assert recovery.ping_with_ack?(:application_data, now: 0.0)
    send_packet(recovery, :one_rtt, now: 1.0)
    refute recovery.ping_with_ack?(:application_data, now: 1.34)
    send_packet(recovery, :one_rtt, now: 1.1, ack_eliciting: false, in_flight: false)
    refute recovery.ping_with_ack?(:application_data, now: 1.2)
    assert recovery.ping_with_ack?(:application_data, now: 1.34)
  end
end
