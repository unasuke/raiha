require "test_helper"
require "support/quic_recovery"

# Loss recovery's design, "Processing ACKs" and "RTT samples", up to the
# congestion controller's on_ack; losses have tests of their own.
class RaihaQUICRecoveryAckTest < Minitest::Test
  include QUICRecovery

  # NewReno that keeps what on_ack was told.
  class Spy < Raiha::QUIC::Congestion::NewReno
    attr_reader :acks

    def on_ack(**keywords)
      (@acks ||= []) << keywords
      super
    end
  end

  def spied
    config = QUIC::Config.new(congestion_control: Spy)
    recovery(config:, path: QUIC::Path.new(config:))
  end

  def test_acknowledged_packets_come_back_in_order
    recovery = recovery()
    3.times { send_packet(recovery, :initial, now: 0.0) }
    outcome = recovery.on_ack_received(packet_type: :initial, ack: ack(2..2, 0..0), now: 0.1)
    assert_equal [0, 2], outcome.acked.map(&:packet_number)
    assert_empty outcome.lost
    assert_equal [1200, 1, 12_000 + 2400], [recovery.path.bytes_in_flight, recovery.path.ack_eliciting_in_flight, recovery.path.congestion.window]
    assert_same QUIC::Recovery::Outcome::NONE, recovery.on_ack_received(packet_type: :initial, ack: ack(2..2), now: 0.2)
  end

  # RFC 9002 "Generating RTT Samples": from the largest acknowledged, sent
  # ack-eliciting, the first time it is acknowledged.
  def test_rtt_sample
    recovery = recovery()
    send_packet(recovery, :handshake, now: 1.0)
    send_packet(recovery, :handshake, now: 1.1)
    recovery.on_ack_received(packet_type: :handshake, ack: ack(1..1, delay: 0.01), now: 1.2)
    rtt = recovery.path.rtt
    assert_in_delta 0.1, rtt.latest_rtt
    assert_equal 1.2, rtt.first_sample_at
    # Packet 0 now, but not the largest: no sample.
    recovery.on_ack_received(packet_type: :handshake, ack: ack(0..1), now: 2.0)
    assert_in_delta 0.1, rtt.latest_rtt
  end

  def test_no_sample_without_an_ack_eliciting_packet
    recovery = recovery()
    send_packet(recovery, :handshake, now: 1.0, ack_eliciting: false, in_flight: false)
    recovery.on_ack_received(packet_type: :handshake, ack: ack(0..0), now: 1.5)
    assert_nil recovery.path.rtt.first_sample_at
  end

  # The ACK Delay of an Initial ACK counts for nothing; a packet kept for
  # its keys counts from when it came.
  def test_ack_delay_and_arrival
    recovery = recovery()
    2.times { |i| send_packet(recovery, :initial, now: i * 0.1) }
    recovery.on_ack_received(packet_type: :initial, ack: ack(0..0), now: 0.1)
    recovery.on_ack_received(packet_type: :initial, ack: ack(1..1, delay: 0.05), now: 0.35, received_at: 0.3)
    assert_in_delta 0.2, recovery.path.rtt.latest_rtt
    assert_in_delta 0.875 * 0.1 + 0.125 * 0.2, recovery.path.rtt.smoothed_rtt
    other = recovery()
    2.times { |i| send_packet(other, :handshake, now: i * 0.1) }
    other.on_ack_received(packet_type: :handshake, ack: ack(0..0), now: 0.1)
    other.on_ack_received(packet_type: :handshake, ack: ack(1..1, delay: 0.05), now: 0.3)
    assert_in_delta 0.875 * 0.1 + 0.125 * 0.15, other.path.rtt.smoothed_rtt
  end

  # #259's on_ack: the latest sample only with the ACK that took it.
  def test_what_the_congestion_controller_hears
    recovery = spied
    send_packet(recovery, :initial, now: 1.0)
    send_packet(recovery, :initial, now: 1.1, sent_bytes: 300)
    recovery.path.transmission_stopped(:drained, waiting: false, next_packet_number: 0)
    recovery.on_ack_received(packet_type: :initial, ack: ack(0..1), now: 1.3)
    send_packet(recovery, :initial, now: 1.4)
    recovery.on_ack_received(packet_type: :initial, ack: ack(2..2, 0..0), now: 1.5)
    first, second = recovery.path.congestion.acks
    assert_equal [1500, 1.1, true], first.values_at(:acked_bytes, :largest_acked_sent_at, :app_limited)
    assert_in_delta 0.2, first[:latest_rtt]
    assert_in_delta 0.2, first[:min_rtt]
    assert_in_delta 0.1, second[:latest_rtt]
  end

  # RFC 9000 "Migration": what was sent on a path that is gone counts for
  # nothing, though its owners still hear of it.
  def test_an_abandoned_path
    recovery = spied
    send_packet(recovery, :handshake, now: 1.0)
    recovery.path.abandon
    outcome = recovery.on_ack_received(packet_type: :handshake, ack: ack(0..0), now: 1.2)
    assert_equal [0], outcome.acked.map(&:packet_number)
    assert_equal 1200, recovery.path.bytes_in_flight
    assert_nil recovery.path.rtt.first_sample_at
    assert_nil recovery.path.congestion.acks
  end

  # RFC 9002 "Handshakes and New Paths".
  def test_peer_completed_address_validation
    assert recovery(role: :server).peer_completed_address_validation?
    client = recovery(role: :client)
    refute client.peer_completed_address_validation?
    send_packet(client, :initial, now: 0.0)
    client.on_ack_received(packet_type: :initial, ack: ack(0..0), now: 0.1)
    refute client.peer_completed_address_validation?
    send_packet(client, :handshake, now: 0.2)
    client.on_ack_received(packet_type: :handshake, ack: ack(0..0), now: 0.3)
    assert client.peer_completed_address_validation?
    confirmed = recovery(role: :client)
    confirmed.handshake_confirmed!(now: 0.0)
    assert confirmed.peer_completed_address_validation?
  end

  def test_an_ack_of_what_was_never_sent_raises
    recovery = recovery()
    send_packet(recovery, :initial, now: 0.0)
    error = assert_raises(QUIC::Violation) { recovery.on_ack_received(packet_type: :initial, ack: ack(1..1, ecn: QUIC::Wire::Frame::Ack::ECNCounts.new(ect0: 0, ect1: 0, ce: 0)), now: 0.1) }
    assert_equal 0x03, error.frame_type
  end

  # Loss recovery's design, "metrics_updated": what changed, at once.
  def test_metrics_are_traced
    tracer = RecordingTracer.new
    recovery = recovery(tracer:)
    send_packet(recovery, :initial, now: 0.0)
    send_packet(recovery, :initial, now: 0.0)
    recovery.on_ack_received(packet_type: :initial, ack: ack(0..0), now: 0.1)
    recovery.on_ack_received(packet_type: :initial, ack: ack(1..1), now: 0.1)
    first, second = tracer.of(:metrics_updated)
    assert_equal({ now: 0.1, latest_rtt: 0.1, smoothed_rtt: 0.1, min_rtt: 0.1, rtt_variance: 0.05, pto_count: 0, bytes_in_flight: 1200,
                   packets_in_flight: 1, congestion_window: 13_200, pacing_rate: 2_112_000 }, first)
    assert_in_delta 0.0375, second.delete(:rtt_variance)
    assert_equal({ now: 0.1, bytes_in_flight: 0, packets_in_flight: 0, congestion_window: 14_400, pacing_rate: 2_304_000 }, second)
  end
end
