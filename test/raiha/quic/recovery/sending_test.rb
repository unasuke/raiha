require "test_helper"
require "support/quic_recovery"

class RaihaNextQUICRecoverySendingTest < Minitest::Test
  include NextQUICRecovery

  # Loss recovery's design, "Tracer": the constants, once at the start.
  def test_recovery_parameters_are_traced
    tracer = RecordingTracer.new
    recovery(tracer:, now: 5.0)
    assert_equal [{ now: 5.0, reordering_threshold: 3, time_threshold: 1.125, timer_granularity: 0.001, initial_rtt: 0.333,
                    max_datagram_size: 1200, initial_congestion_window: 12_000, minimum_congestion_window: 2400,
                    persistent_congestion_threshold: 3 }], tracer.of(:recovery_parameters_set)
  end

  # 0-RTT and 1-RTT share the Application Data numbers.
  def test_packet_numbers_by_space
    recovery = recovery()
    assert_equal [0, 1, 0, 0, 1, 2], %i[initial initial handshake zero_rtt one_rtt one_rtt].map { |type| recovery.next_packet_number(type) }
    assert_raises(KeyError) { recovery.next_packet_number(:retry) }
  end

  # Loss recovery's design, "Packet number skipping": Application Data only,
  # once the handshake is confirmed, after twice the initial window, half the
  # window and up to one and a half windows more, in datagrams.
  def test_skips
    recovery = recovery()
    assert_equal (0...100).to_a, Array.new(100) { recovery.next_packet_number(:one_rtt) }
    recovery.handshake_confirmed!(now: 0.0)
    numbers = Array.new(100) { recovery.next_packet_number(:one_rtt) }
    skipped = ((100..numbers.last).to_a - numbers)
    assert_equal 1, skipped.size
    assert_includes (100 + 25)..(100 + 40), skipped.first
    assert_equal (0...100).to_a, Array.new(100) { recovery.next_packet_number(:handshake) }
  end

  def test_on_packet_sent
    recovery = recovery()
    send_packet(recovery, :initial, now: 1.0, duties: [QUIC::Recovery::Duty::Crypto.new(space: :initial, offset: 0, length: 1000)])
    send_packet(recovery, :initial, now: 1.1, sent_bytes: 40, ack_eliciting: false, in_flight: false)
    assert_equal [1200, 1], [recovery.path.bytes_in_flight, recovery.path.ack_eliciting_in_flight]
    packet = recovery.on_packet_sent(packet_type: :one_rtt, packet_number: recovery.next_packet_number(:one_rtt), sent_bytes: 1200,
      ack_eliciting: true, in_flight: true, duties: [QUIC::Recovery::Duty::HandshakeDone.new], now: 1.2)
    assert_same recovery.path, packet.path
    assert packet.duties.frozen?
    assert_equal [1.2, 2400], [packet.time_sent, recovery.path.bytes_in_flight]
  end

  # RFC 9000 appendix A.2: twice the packets not yet acknowledged.
  def test_packet_number_length
    recovery = recovery()
    assert_equal 1, recovery.packet_number_length(:handshake, 0)
    300.times { send_packet(recovery, :handshake, now: 0.0) }
    assert_equal 2, recovery.packet_number_length(:handshake, 300)
    recovery.on_ack_received(packet_type: :handshake, ack: ack(299..299), now: 0.1)
    assert_equal 1, recovery.packet_number_length(:handshake, 300)
  end

  def test_largest_received
    recovery = recovery()
    assert_nil recovery.largest_received(:one_rtt)
    recovery.on_packet_received(packet_type: :one_rtt, packet_number: 7, ecn: :not_ect, ack_eliciting: true, now: 0.0)
    recovery.on_packet_received(packet_type: :zero_rtt, packet_number: 3, ecn: :not_ect, ack_eliciting: true, now: 0.0)
    assert_equal 7, recovery.largest_received(:zero_rtt)
  end

  # What a probe carries again when nothing new waits.
  def test_oldest_ack_eliciting
    recovery = recovery()
    assert_nil recovery.oldest_ack_eliciting(:handshake)
    send_packet(recovery, :handshake, now: 0.0, ack_eliciting: false, in_flight: false)
    send_packet(recovery, :handshake, now: 0.1)
    send_packet(recovery, :handshake, now: 0.2)
    assert_equal 1, recovery.oldest_ack_eliciting(:handshake).packet_number
    recovery.on_ack_received(packet_type: :handshake, ack: ack(1..1), now: 0.3)
    assert_equal 2, recovery.oldest_ack_eliciting(:handshake).packet_number
  end
end
