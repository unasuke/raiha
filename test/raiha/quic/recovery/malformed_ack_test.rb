require "test_helper"
require "support/quic_recovery"

# Loss recovery's design, "Malformed ACKs": what a peer may send to break
# loss recovery or wear the endpoint out, each rejected or held within its
# bound.
class RaihaQUICRecoveryMalformedAckTest < Minitest::Test
  include QUICRecovery

  ECNCounts = QUIC::Wire::Frame::Ack::ECNCounts

  # NewReno that keeps the CE marks it was told of.
  class Spy < Raiha::QUIC::Congestion::NewReno
    def ce = @ce ||= []

    def on_ecn_ce(**keywords)
      ce << keywords
      super
    end
  end

  def spied(role: :server)
    config = QUIC::Config.new(congestion_control: Spy)
    recovery(role:, config:, path: QUIC::Path.new(config:))
  end

  # The congestion window, what is in flight and when the first RTT sample
  # was taken.
  def state(recovery) = [recovery.path.congestion.window, recovery.path.bytes_in_flight, recovery.path.rtt.first_sample_at]

  def assert_violation(recovery, packet_type, *ranges)
    before = state(recovery)
    error = assert_raises(QUIC::Violation) { recovery.on_ack_received(packet_type:, ack: ack(*ranges), now: 1.0) }
    assert_equal QUIC::ErrorCode::PROTOCOL_VIOLATION, error.code
    assert_equal before, state(recovery)
  end

  # An ACK of a number above the largest sent, with one sent among it.
  def test_beyond_the_largest_sent
    recovery = spied
    3.times { send_packet(recovery, :handshake, now: 0.0) }
    assert_violation(recovery, :handshake, 3..3, 0..1)
  end

  # An ACK of the number left out, which only a peer that guesses would
  # acknowledge.
  def test_the_skipped_number
    recovery = spied
    recovery.handshake_confirmed!(now: 0.0)
    numbers = Array.new(100) { send_packet(recovery, :one_rtt, now: 0.0) }
    skipped = (0..numbers.last).to_a - numbers
    assert_equal 1, skipped.size
    assert_violation(recovery, :one_rtt, (skipped.first - 1)..(skipped.first + 1))
  end

  # An ACK of a 0-RTT packet after the server rejected 0-RTT.
  def test_a_rejected_0rtt_packet
    recovery = spied(role: :client)
    2.times { send_packet(recovery, :zero_rtt, now: 0.0) }
    send_packet(recovery, :one_rtt, now: 0.0)
    recovery.on_zero_rtt_rejected(now: 0.1)
    assert_violation(recovery, :one_rtt, 1..2)
  end

  # 0 to the largest again and again: each ACK goes through no more than
  # its ranges and the records left.
  def test_the_same_wide_ack_again_and_again
    space = QUIC::Recovery::PacketNumberSpace.new(:application_data)
    path = QUIC::Path.new(config: QUIC::Config.new)
    add = lambda do
      space.add(QUIC::Recovery::SentPacket.new(packet_number: space.next_packet_number, time_sent: 0.0, sent_bytes: 1200,
        ack_eliciting: true, in_flight: true, path:, duties: [].freeze, pmtu_probe: false, ecn: :not_ect))
    end
    10_000.times { add.call }
    assert_equal 10_000, space.acknowledge([0..9_999], frame_type: 0x02).size
    add.call
    steps = Array.new(1000) do
      space.acknowledge([0..10_000], frame_type: 0x02)
      space.ack_steps
    end
    assert_operator steps.max, :<=, 2
  end

  # The ACK Range Count says 2^62 - 1 ranges and one is there: nothing is
  # made ready for the count.
  def test_a_range_count_that_lies
    error = assert_raises(QUIC::Wire::Malformed) do
      QUIC::Wire::Frame.parse("\x02\x0a\x00\xff\xff\xff\xff\xff\xff\xff\xff\x02\x01\x03".b, packet_type: :one_rtt, ack_delay_exponent: 3)
    end
    assert_equal QUIC::ErrorCode::FRAME_ENCODING_ERROR, error.code
  end

  # ECN counts of more ECT(0) than was sent fail the path: it stops
  # marking and heeds no CE marks from then on.
  def test_ecn_counts_that_lie
    recovery = spied
    4.times { send_packet(recovery, :handshake, now: 0.0) }
    recovery.on_ack_received(packet_type: :handshake, ack: ack(0..1, ecn: ECNCounts.new(ect0: 10, ect1: 0, ce: 0)), now: 0.1)
    assert_equal [:failed, :not_ect], [recovery.path.ecn_state, recovery.path.ecn]
    recovery.on_ack_received(packet_type: :handshake, ack: ack(0..3, ecn: ECNCounts.new(ect0: 10, ect1: 0, ce: 2)), now: 0.2)
    assert_empty recovery.path.congestion.ce
  end

  # A flood of packets of only ACKs, which the peer need never
  # acknowledge: no more than 1000 records stay.
  def test_packets_of_only_acks
    recovery = spied
    5000.times { send_packet(recovery, :handshake, now: 0.0, ack_eliciting: false, in_flight: false) }
    assert_equal 1000, recovery.on_ack_received(packet_type: :handshake, ack: ack(0..4999), now: 0.1).acked.size
  end

  # Many losses: no more than 64 records of them stay.
  def test_many_losses
    recovery = spied
    1000.times { send_packet(recovery, :handshake, now: 0.0) }
    assert_equal 997, recovery.on_ack_received(packet_type: :handshake, ack: ack(999..999), now: 0.1).lost.size
    recovery.on_ack_received(packet_type: :handshake, ack: ack(0..999), now: 0.2)
    assert_equal 64, recovery.packets_spuriously_lost
  end
end
