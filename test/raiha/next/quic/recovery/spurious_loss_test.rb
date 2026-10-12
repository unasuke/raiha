require "raiha/next/test_helper"
require "raiha/next/support/quic_recovery"

# Loss recovery's design, "Lost packets kept" and "Acknowledged after all".
class RaihaNextQUICRecoverySpuriousLossTest < Minitest::Test
  include NextQUICRecovery

  # NewReno that keeps the bytes each ACK told it of.
  class Spy < Raiha::Next::QUIC::Congestion::NewReno
    def acked_bytes = @acked_bytes ||= []

    def on_ack(acked_bytes:, **)
      self.acked_bytes << acked_bytes
      super
    end
  end

  def spied(tracer: nil)
    config = QUIC::Config.new(congestion_control: Spy)
    recovery(role: :server, config:, path: QUIC::Path.new(config:), tracer:)
  end

  # Packet 0 declared lost by the threshold, then acknowledged.
  def test_a_lost_packet_acknowledged_after_all
    tracer = RecordingTracer.new
    recovery = spied(tracer:)
    5.times { send_packet(recovery, :handshake, now: 0.0) }
    assert_equal [0, 1], recovery.on_ack_received(packet_type: :handshake, ack: ack(4..4), now: 0.1).lost.map(&:packet_number)
    in_flight = recovery.path.bytes_in_flight
    rtt = recovery.path.rtt.smoothed_rtt
    outcome = recovery.on_ack_received(packet_type: :handshake, ack: ack(4..4, 0..0), now: 0.3)
    assert_equal [0], outcome.acked.map(&:packet_number)
    assert_equal [1, in_flight, rtt], [recovery.packets_spuriously_lost, recovery.path.bytes_in_flight, recovery.path.rtt.smoothed_rtt]
    assert_equal [1200], recovery.path.congestion.acked_bytes
    assert_equal [{ packet_number: 0, space: :handshake, now: 0.3 }], tracer.of(:spurious_loss)
  end

  # With a new acknowledgment too, both come back and only the new one
  # counts for the congestion controller.
  def test_together_with_a_new_acknowledgment
    recovery = spied
    6.times { send_packet(recovery, :handshake, now: 0.0) }
    recovery.on_ack_received(packet_type: :handshake, ack: ack(4..4), now: 0.1)
    outcome = recovery.on_ack_received(packet_type: :handshake, ack: ack(5..5, 0..0), now: 0.3)
    assert_equal [5, 0], outcome.acked.map(&:packet_number)
    assert_equal [1200, 1200], recovery.path.congestion.acked_bytes
  end

  # Packets 0 to 97 lost by the threshold; the latest 64 are kept.
  def test_kept_up_to_64
    recovery = spied
    101.times { send_packet(recovery, :handshake, now: 0.0) }
    assert_equal 98, recovery.on_ack_received(packet_type: :handshake, ack: ack(100..100), now: 0.1).lost.size
    outcome = recovery.on_ack_received(packet_type: :handshake, ack: ack(0..100), now: 0.2)
    assert_equal [98, 99, *34..97], outcome.acked.map(&:packet_number)
    assert_equal 64, recovery.packets_spuriously_lost
  end

  # Forgotten three PTOs after they were sent.
  def test_forgotten_after_three_ptos
    recovery = spied
    5.times { send_packet(recovery, :handshake, now: 0.0) }
    recovery.on_ack_received(packet_type: :handshake, ack: ack(4..4), now: 0.1)
    send_packet(recovery, :handshake, now: 10.0)
    recovery.on_ack_received(packet_type: :handshake, ack: ack(5..5), now: 10.1)
    outcome = recovery.on_ack_received(packet_type: :handshake, ack: ack(4..5, 0..1), now: 10.2)
    assert_empty outcome.acked
  end
end
