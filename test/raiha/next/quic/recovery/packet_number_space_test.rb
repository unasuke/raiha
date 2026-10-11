require "raiha/next/test_helper"
require "raiha/next/quic"

class RaihaNextQUICRecoveryPacketNumberSpaceTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
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
end
