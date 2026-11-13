require "test_helper"
require "support/quic_recovery"

# RFC 9002 "Acknowledgment-Based Detection", as loss recovery's design
# applies it on an ACK.
class RaihaNextQUICRecoveryLossDetectionTest < Minitest::Test
  include NextQUICRecovery

  # NewReno that keeps the order of what it was told.
  class Spy < Raiha::QUIC::Congestion::NewReno
    def calls = @calls ||= []

    def on_loss(**keywords)
      calls << [:on_loss, keywords]
      super
    end

    def on_ack(**keywords)
      calls << [:on_ack, keywords]
      super
    end
  end

  def spied(tracer: nil)
    config = QUIC::Config.new(congestion_control: Spy)
    recovery(config:, path: QUIC::Path.new(config:), tracer:)
  end

  def numbers(packets) = packets.map(&:packet_number)

  # Three packets below the largest acknowledged.
  def test_packet_threshold
    recovery = recovery()
    5.times { send_packet(recovery, :handshake, now: 0.0) }
    outcome = recovery.on_ack_received(packet_type: :handshake, ack: ack(4..4), now: 0.05)
    assert_equal [[4], [0, 1]], [numbers(outcome.acked), numbers(outcome.lost)]
    assert_equal [2400, 2], [recovery.path.bytes_in_flight, recovery.packets_lost]
  end

  # 9/8 of the RTT before the ACK; until then, a time to declare it lost.
  def test_time_threshold
    recovery = recovery()
    send_packet(recovery, :handshake, now: 0.0)
    send_packet(recovery, :handshake, now: 0.0)
    send_packet(recovery, :handshake, now: 0.5)
    outcome = recovery.on_ack_received(packet_type: :handshake, ack: ack(2..2), now: 0.6)
    assert_equal [0, 1], numbers(outcome.lost)
    other = recovery()
    send_packet(other, :handshake, now: 0.0)
    send_packet(other, :handshake, now: 0.0)
    outcome = other.on_ack_received(packet_type: :handshake, ack: ack(1..1), now: 0.1)
    assert_empty outcome.lost
  end

  # Packets above the largest acknowledged are not looked at, however old.
  def test_only_below_the_largest_acknowledged
    recovery = recovery()
    send_packet(recovery, :handshake, now: 0.0)
    recovery.on_ack_received(packet_type: :handshake, ack: ack(0..0), now: 0.1)
    send_packet(recovery, :initial, now: 0.0)
    send_packet(recovery, :initial, now: 0.0, ack_eliciting: false)
    5.times { send_packet(recovery, :initial, now: 0.001) }
    outcome = recovery.on_ack_received(packet_type: :initial, ack: ack(1..1), now: 10.0)
    assert_equal [0], numbers(outcome.lost)
  end

  # Loss recovery's design, "Processing ACKs": on_loss before on_ack, once a
  # path, with the latest time a lost packet was sent.
  def test_the_congestion_controller_hears_of_losses_first
    recovery = spied
    send_packet(recovery, :handshake, now: 0.0)
    send_packet(recovery, :handshake, now: 0.01, sent_bytes: 500)
    3.times { send_packet(recovery, :handshake, now: 0.02) }
    recovery.on_ack_received(packet_type: :handshake, ack: ack(4..4), now: 0.05)
    calls = recovery.path.congestion.calls
    assert_equal %i[on_loss on_ack], calls.map(&:first)
    assert_equal({ lost_bytes: 1700, largest_lost_sent_at: 0.01, persistent: false, now: 0.05 }, calls.first.last)
    assert_equal 6000, recovery.path.congestion.window
  end

  # A lost probe of the path MTU leaves the window alone.
  def test_a_lost_mtu_probe_tells_the_controller_nothing
    recovery = spied
    number = recovery.next_packet_number(:one_rtt)
    recovery.on_packet_sent(packet_type: :one_rtt, packet_number: number, sent_bytes: 1500, ack_eliciting: true, in_flight: true,
      duties: [], now: 0.0, pmtu_probe: true)
    3.times { send_packet(recovery, :one_rtt, now: 0.01) }
    outcome = recovery.on_ack_received(packet_type: :one_rtt, ack: ack(3..3), now: 0.05)
    assert_equal [0], numbers(outcome.lost)
    assert_equal [:on_ack], recovery.path.congestion.calls.map(&:first)
    assert_equal 2400, recovery.path.bytes_in_flight
  end

  def test_losses_are_traced
    tracer = RecordingTracer.new
    recovery = recovery(tracer:)
    send_packet(recovery, :handshake, now: 0.0)
    send_packet(recovery, :handshake, now: 0.5)
    send_packet(recovery, :handshake, now: 0.5)
    send_packet(recovery, :handshake, now: 0.5)
    recovery.on_ack_received(packet_type: :handshake, ack: ack(3..3), now: 0.6)
    assert_equal [{ packet_number: 0, space: :handshake, trigger: :reordering_threshold, mtu_probe: false, now: 0.6 }],
      tracer.of(:packet_lost)
    other_tracer = RecordingTracer.new
    other = recovery(tracer: other_tracer)
    send_packet(other, :handshake, now: 0.0)
    send_packet(other, :handshake, now: 0.5)
    other.on_ack_received(packet_type: :handshake, ack: ack(1..1), now: 0.6)
    assert_equal [:time_threshold], other_tracer.of(:packet_lost).map { _1[:trigger] }
  end
end
