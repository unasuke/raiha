require "test_helper"
require "raiha/quic"

class RaihaQUICRecoveryPacketNumberSpaceTest < Minitest::Test
  QUIC = Raiha::QUIC
  Space = QUIC::Recovery::PacketNumberSpace

  def packet(number, time_sent:, ack_eliciting: true, in_flight: true)
    @path ||= QUIC::Path.new(config: QUIC::Config.new)
    QUIC::Recovery::SentPacket.new(packet_number: number, time_sent:, sent_bytes: 1200, ack_eliciting:, in_flight:,
      path: @path, duties: [].freeze, pmtu_probe: false, ecn: :not_ect)
  end

  def test_packet_numbers_count_up
    space = Space.new(:initial)
    assert_equal [0, 1, 2], Array.new(3) { space.next_packet_number }
    refute space.skipping?
  end

  # Loss recovery's design, "Packet number skipping": one number left out,
  # and no other until it is shown.
  def test_skip
    space = Space.new(:application_data)
    space.skip_after(2)
    assert space.skipping?
    assert_equal [0, 1, 3, 4], Array.new(4) { space.next_packet_number }
    assert_equal 2, space.skipped
    assert space.skipping?
    assert_raises(ArgumentError) { space.skip_after(5) }
    space = Space.new(:application_data)
    space.skip_after(0)
    assert_equal 1, space.next_packet_number
  end

  def test_records
    space = Space.new(:handshake)
    assert_equal [nil, nil, 0], [space.largest_sent, space.time_of_last_ack_eliciting_packet, space.ack_eliciting_in_flight]
    space.add(packet(0, time_sent: 1.0))
    space.add(packet(1, time_sent: 1.5, ack_eliciting: false, in_flight: false))
    assert_equal [1, 1.0, 1], [space.largest_sent, space.time_of_last_ack_eliciting_packet, space.ack_eliciting_in_flight]
    assert space.sent?(1)
    refute space.sent?(2)
  end

  def filled(count, ack_eliciting: true)
    space = Space.new(:application_data)
    count.times { |i| space.add(packet(space.next_packet_number, time_sent: i.to_f, ack_eliciting:)) }
    space
  end

  def numbers(packets) = packets.map(&:packet_number)

  def test_acknowledge
    space = filled(10)
    assert_equal [0, 1, 2, 5, 6, 7, 8, 9], numbers(space.acknowledge([5..9, 0..2], frame_type: 0x02))
    assert_equal [9, 2], [space.largest_acked_packet, space.ack_eliciting_in_flight]
    assert space.sent?(3)
    # Acknowledged again: nothing new, and no error.
    assert_empty space.acknowledge([5..9], frame_type: 0x02)
    assert_equal [3], numbers(space.acknowledge([3..3], frame_type: 0x02))
    assert_equal 9, space.largest_acked_packet
  end

  # Loss recovery's design, "Validation".
  def test_an_ack_of_what_was_never_sent
    error = assert_raises(QUIC::Violation) { Space.new(:initial).acknowledge([0..0], frame_type: 0x02) }
    assert_equal [QUIC::ErrorCode::PROTOCOL_VIOLATION, 0x02], [error.code, error.frame_type]
    space = filled(5)
    error = assert_raises(QUIC::Violation) { space.acknowledge([5..5, 0..3], frame_type: 0x03) }
    assert_equal 0x03, error.frame_type
    assert_nil space.largest_acked_packet
    assert space.sent?(0)
  end

  def test_an_ack_of_the_skipped_number
    space = Space.new(:application_data)
    space.skip_after(3)
    6.times { |i| space.add(packet(space.next_packet_number, time_sent: i.to_f)) }
    assert_equal 3, space.skipped
    assert_raises(QUIC::Violation) { space.acknowledge([2..4], frame_type: 0x02) }
    assert_equal [0, 1, 2], numbers(space.acknowledge([0..2], frame_type: 0x02))
    assert_equal 3, space.skipped
    # A larger number acknowledged without the skipped one shows it.
    assert_equal [4, 5, 6], numbers(space.acknowledge([4..6], frame_type: 0x02))
    assert_nil space.skipped
    refute space.skipping?
  end

  # Loss recovery's design, "Walking the ranges": no more steps than the
  # records, however wide the ranges, and no more than the width, however
  # many the records.
  def test_steps_stay_within_the_records_or_the_width
    space = filled(1000)
    space.acknowledge([0..989], frame_type: 0x02)
    space.acknowledge([0..999], frame_type: 0x02)
    assert_operator space.ack_steps, :<=, 10
    space = filled(1000)
    space.acknowledge([500..501], frame_type: 0x02)
    assert_operator space.ack_steps, :<=, 2
    space = filled(1000)
    acked = space.acknowledge((0...500).map { |i| (998 - 2 * i)..(998 - 2 * i) }, frame_type: 0x02)
    assert_equal 500, acked.size
    assert_operator space.ack_steps, :<=, 1000
  end

  # Loss recovery's design, "Limits": the packets of only ACKs after the
  # last ack-eliciting one are kept up to 1000.
  def test_ack_only_records_are_kept_up_to_1000
    space = Space.new(:application_data)
    space.add(packet(space.next_packet_number, time_sent: 0.0))
    1005.times { space.add(packet(space.next_packet_number, time_sent: 0.0, ack_eliciting: false, in_flight: false)) }
    refute space.sent?(5)
    assert space.sent?(6)
    assert space.sent?(0)
    assert_equal [0, 6], numbers(space.acknowledge([6..6, 0..5], frame_type: 0x02))
    # An ack-eliciting packet starts the tail over.
    space.add(packet(space.next_packet_number, time_sent: 0.0))
    2.times { space.add(packet(space.next_packet_number, time_sent: 0.0, ack_eliciting: false, in_flight: false)) }
    assert space.sent?(1007)
  end
end
