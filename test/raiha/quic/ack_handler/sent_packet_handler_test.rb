require "test_helper"
require "raiha/quic/ack_handler"
require "raiha/quic/wire/frames/ack_frame"

class RaihaQuicAckHandlerSentPacketHandlerTest < Minitest::Test
  def test_sent_packet_tracking
    handler = Raiha::Quic::AckHandler::SentPacketHandler.new

    packet_number = handler.get_next_packet_number(:application_data)
    assert_equal 0, packet_number.value

    handler.sent_packet(
      packet_number: packet_number,
      frames: [],
      size: 1200,
      ack_eliciting: true,
      pn_space: :application_data
    )

    assert_equal 1200, handler.bytes_in_flight
  end

  def test_non_ack_eliciting_not_in_flight
    handler = Raiha::Quic::AckHandler::SentPacketHandler.new

    handler.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(0),
      frames: [],
      size: 100,
      ack_eliciting: false,
      pn_space: :application_data
    )

    assert_equal 0, handler.bytes_in_flight
  end

  def test_received_ack_removes_packets
    handler = Raiha::Quic::AckHandler::SentPacketHandler.new

    3.times do |i|
      handler.sent_packet(
        packet_number: Raiha::Quic::Protocol::PacketNumber.new(i),
        frames: [],
        size: 100,
        ack_eliciting: true,
        pn_space: :application_data
      )
    end

    assert_equal 300, handler.bytes_in_flight

    ack_frame = Raiha::Quic::Wire::Frames::AckFrame.new
    ack_frame.largest_acknowledged = 2
    ack_frame.ack_delay = 0
    ack_frame.ack_ranges = [
      Raiha::Quic::Wire::Frames::AckFrame::AckRange.new(gap: 0, ack_range_length: 2)
    ]

    handler.received_ack(ack_frame, pn_space: :application_data)
    assert_equal 0, handler.bytes_in_flight
  end

  def test_packet_number_spaces_are_independent
    handler = Raiha::Quic::AckHandler::SentPacketHandler.new

    initial_pn = handler.get_next_packet_number(:initial)
    handshake_pn = handler.get_next_packet_number(:handshake)
    app_pn = handler.get_next_packet_number(:application_data)

    assert_equal 0, initial_pn.value
    assert_equal 0, handshake_pn.value
    assert_equal 0, app_pn.value
  end

  def test_sequential_packet_numbers
    handler = Raiha::Quic::AckHandler::SentPacketHandler.new

    assert_equal 0, handler.get_next_packet_number(:application_data).value
    assert_equal 1, handler.get_next_packet_number(:application_data).value
    assert_equal 2, handler.get_next_packet_number(:application_data).value
  end
end
