require "raiha/next/test_helper"
require "raiha/next/support/quic_recovery"

# RFC 9001 "Rejecting 0-RTT", as loss recovery's design, "On a rejected
# 0-RTT", applies it.
class RaihaNextQUICRecoveryZeroRttRejectionTest < Minitest::Test
  include NextQUICRecovery

  def test_the_0rtt_packets_go
    recovery = recovery(role: :client)
    2.times { send_packet(recovery, :zero_rtt, now: 0.0) }
    send_packet(recovery, :one_rtt, now: 0.1)
    recovery.on_zero_rtt_rejected(now: 0.2)
    assert_equal [1200, 1], [recovery.path.bytes_in_flight, recovery.path.packets_in_flight]
    # An ACK of a 0-RTT packet now breaks RFC 9001's rule; the 1-RTT one is fine.
    error = assert_raises(QUIC::Violation) { recovery.on_ack_received(packet_type: :one_rtt, ack: ack(2..2, 0..0), now: 0.3) }
    assert_equal QUIC::ErrorCode::PROTOCOL_VIOLATION, error.code
    assert_equal [2], recovery.on_ack_received(packet_type: :one_rtt, ack: ack(2..2), now: 0.3).acked.map(&:packet_number)
  end

  # Before any 1-RTT packet, every Application Data packet was 0-RTT.
  def test_all_of_them_before_any_1rtt
    recovery = recovery(role: :client)
    send_packet(recovery, :initial, now: 0.0)
    3.times { send_packet(recovery, :zero_rtt, now: 0.0) }
    recovery.on_zero_rtt_rejected(now: 0.1)
    assert_equal 1200, recovery.path.bytes_in_flight
    send_packet(recovery, :one_rtt, now: 0.2)
    assert_raises(QUIC::Violation) { recovery.on_ack_received(packet_type: :one_rtt, ack: ack(3..3, 1..1), now: 0.3) }
    assert_equal [3], recovery.on_ack_received(packet_type: :one_rtt, ack: ack(3..3), now: 0.3).acked.map(&:packet_number)
  end
end
