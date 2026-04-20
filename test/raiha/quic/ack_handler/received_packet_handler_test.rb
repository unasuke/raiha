require "test_helper"
require "raiha/quic/ack_handler"

class RaihaQuicAckHandlerReceivedPacketHandlerTest < Minitest::Test
  def test_record_received_packet
    handler = Raiha::Quic::AckHandler::ReceivedPacketHandler.new

    result = handler.received_packet(
      packet_number: 0, pn_space: :application_data, ack_eliciting: true
    )
    assert result
  end

  def test_duplicate_detection
    handler = Raiha::Quic::AckHandler::ReceivedPacketHandler.new

    handler.received_packet(packet_number: 0, pn_space: :application_data, ack_eliciting: true)
    result = handler.received_packet(packet_number: 0, pn_space: :application_data, ack_eliciting: true)
    refute result
  end

  def test_should_send_ack_after_two_ack_eliciting
    handler = Raiha::Quic::AckHandler::ReceivedPacketHandler.new

    handler.received_packet(packet_number: 0, pn_space: :application_data, ack_eliciting: true)
    refute handler.should_send_ack?(:application_data)

    handler.received_packet(packet_number: 1, pn_space: :application_data, ack_eliciting: true)
    assert handler.should_send_ack?(:application_data)
  end

  def test_non_ack_eliciting_does_not_trigger
    handler = Raiha::Quic::AckHandler::ReceivedPacketHandler.new

    handler.received_packet(packet_number: 0, pn_space: :application_data, ack_eliciting: false)
    handler.received_packet(packet_number: 1, pn_space: :application_data, ack_eliciting: false)
    refute handler.should_send_ack?(:application_data)
  end

  def test_get_ack_frame
    handler = Raiha::Quic::AckHandler::ReceivedPacketHandler.new

    handler.received_packet(packet_number: 0, pn_space: :application_data, ack_eliciting: true)
    handler.received_packet(packet_number: 1, pn_space: :application_data, ack_eliciting: true)
    handler.received_packet(packet_number: 2, pn_space: :application_data, ack_eliciting: true)

    frame = handler.get_ack_frame(:application_data)
    refute_nil frame
    assert_equal 2, frame.largest_acknowledged
    assert_equal 1, frame.ack_ranges.length
    assert_equal 2, frame.ack_ranges.first.ack_range_length
  end

  def test_get_ack_frame_with_gap
    handler = Raiha::Quic::AckHandler::ReceivedPacketHandler.new

    handler.received_packet(packet_number: 0, pn_space: :application_data, ack_eliciting: true)
    handler.received_packet(packet_number: 1, pn_space: :application_data, ack_eliciting: true)
    # gap: packet 2 missing
    handler.received_packet(packet_number: 3, pn_space: :application_data, ack_eliciting: true)
    handler.received_packet(packet_number: 4, pn_space: :application_data, ack_eliciting: true)

    frame = handler.get_ack_frame(:application_data)
    assert_equal 4, frame.largest_acknowledged
    assert_equal 2, frame.ack_ranges.length
  end

  def test_get_ack_frame_resets_state
    handler = Raiha::Quic::AckHandler::ReceivedPacketHandler.new

    handler.received_packet(packet_number: 0, pn_space: :application_data, ack_eliciting: true)
    handler.received_packet(packet_number: 1, pn_space: :application_data, ack_eliciting: true)
    assert handler.should_send_ack?(:application_data)

    handler.get_ack_frame(:application_data)
    refute handler.should_send_ack?(:application_data)
  end

  def test_no_ack_frame_when_empty
    handler = Raiha::Quic::AckHandler::ReceivedPacketHandler.new
    assert_nil handler.get_ack_frame(:application_data)
  end

  def test_spaces_are_independent
    handler = Raiha::Quic::AckHandler::ReceivedPacketHandler.new

    handler.received_packet(packet_number: 0, pn_space: :initial, ack_eliciting: true)
    handler.received_packet(packet_number: 1, pn_space: :initial, ack_eliciting: true)

    assert handler.should_send_ack?(:initial)
    refute handler.should_send_ack?(:application_data)
  end

  def test_ack_frame_carries_ecn_counts_when_ect_seen
    handler = Raiha::Quic::AckHandler::ReceivedPacketHandler.new

    handler.received_packet(packet_number: 0, pn_space: :application_data, ack_eliciting: true, ecn: :ect0)
    handler.received_packet(packet_number: 1, pn_space: :application_data, ack_eliciting: true, ecn: :ce)

    frame = handler.get_ack_frame(:application_data)
    refute_nil frame.ecn_counts
    assert_equal 1, frame.ecn_counts[:ect0]
    assert_equal 0, frame.ecn_counts[:ect1]
    assert_equal 1, frame.ecn_counts[:ecn_ce]
  end

  def test_ack_frame_omits_ecn_counts_when_no_marks_seen
    handler = Raiha::Quic::AckHandler::ReceivedPacketHandler.new

    handler.received_packet(packet_number: 0, pn_space: :application_data, ack_eliciting: true)
    # default ecn: :not_ect

    frame = handler.get_ack_frame(:application_data)
    assert_nil frame.ecn_counts
  end
end
