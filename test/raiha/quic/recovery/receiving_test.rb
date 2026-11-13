require "test_helper"
require "support/quic_recovery"

# Loss recovery's design, "Packet numbers received" and "Duplicates".
class RaihaQUICRecoveryReceivingTest < Minitest::Test
  include QUICRecovery

  Space = QUIC::Recovery::PacketNumberSpace

  def receive(space, *numbers, ecn: :not_ect) = numbers.map { |number| space.receive(number, ecn:, ack_eliciting: false, now: 0.0) }

  def test_in_order_and_out_of_order
    space = Space.new(:application_data)
    assert_equal [true, true, true], receive(space, 0, 1, 2)
    assert_equal [0..2], space.received_ranges
    receive(space, 5, 4, 7)
    assert_equal [7..7, 4..5, 0..2], space.received_ranges
    receive(space, 3)
    assert_equal [7..7, 0..5], space.received_ranges
    receive(space, 6)
    assert_equal [0..7], space.received_ranges
    assert_equal 7, space.largest_received
  end

  # RFC 9000 "Packet Number Spaces": a duplicate is dropped and not counted.
  def test_duplicates
    space = Space.new(:handshake)
    receive(space, 0, 1, 4)
    assert_equal [false, false, false], receive(space, 1, 4, 0, ecn: :ce)
    assert_nil space.received_ecn_counts
  end

  def test_ecn_counts
    space = Space.new(:application_data)
    receive(space, 0, 1, ecn: :ect0)
    receive(space, 2, ecn: :ce)
    receive(space, 3)
    assert_equal QUIC::Wire::Frame::Ack::ECNCounts.new(ect0: 2, ect1: 0, ce: 1), space.received_ecn_counts
  end

  # Past 64 ranges the oldest goes, and what is below it counts as a
  # duplicate.
  def test_at_most_64_ranges
    space = Space.new(:application_data)
    66.times { |i| space.receive(i * 2, ecn: :not_ect, ack_eliciting: false, now: 0.0) }
    ranges = space.received_ranges
    assert_equal [64, 130..130, 4..4], [ranges.size, ranges.first, ranges.last]
    assert_equal 3, space.ignore_below
    assert_equal [false, true], receive(space, 1, 5)
  end

  # RFC 9000 "Limiting Ranges by Tracking ACK Frames".
  def test_acknowledged_up_to
    space = Space.new(:application_data)
    receive(space, 0, 1, 2, 5, 6, 9)
    space.acknowledged_up_to(5)
    assert_equal [9..9, 6..6], space.received_ranges
    assert_equal [false, false], receive(space, 3, 4)
    space.acknowledged_up_to(2)
    assert_equal 6, space.ignore_below
  end

  def test_through_recovery
    recovery = recovery()
    assert recovery.on_packet_received(packet_type: :one_rtt, packet_number: 3, ecn: :ect0, ack_eliciting: true, now: 0.0)
    refute recovery.on_packet_received(packet_type: :zero_rtt, packet_number: 3, ecn: :ect0, ack_eliciting: true, now: 0.0)
    recovery.ack_frame_acknowledged(:application_data, largest: 3)
    refute recovery.on_packet_received(packet_type: :one_rtt, packet_number: 2, ecn: :not_ect, ack_eliciting: true, now: 0.0)
  end

  # Discarding the keys of a space forgets what was received in it too.
  def test_discard_forgets
    recovery = recovery()
    recovery.on_packet_received(packet_type: :handshake, packet_number: 0, ecn: :not_ect, ack_eliciting: true, now: 0.0)
    recovery.discard_space(:handshake, now: 0.0)
    refute recovery.ack_owed?(:handshake)
    assert recovery.on_packet_received(packet_type: :handshake, packet_number: 1, ecn: :not_ect, ack_eliciting: true, now: 0.0)
  end
end
