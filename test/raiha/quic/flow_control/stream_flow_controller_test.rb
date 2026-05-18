require "test_helper"
require "raiha/quic/flow_control"
require "raiha/quic/protocol/stream_id"

class RaihaQuicFlowControlStreamFlowControllerTest < Minitest::Test
  def setup
    @connection_controller = Raiha::Quic::FlowControl::ConnectionFlowController.new(
      receive_window: 1_000_000, send_window: 1_000_000
    )
    @stream_controller = Raiha::Quic::FlowControl::StreamFlowController.new(
      stream_id: Raiha::Quic::Protocol::StreamID.new(0),
      receive_window: 100_000,
      send_window: 100_000,
      connection_flow_controller: @connection_controller
    )
  end

  def test_send_window_limited_by_stream
    assert_equal 100_000, @stream_controller.send_window_size
  end

  def test_send_window_limited_by_connection
    small_connection = Raiha::Quic::FlowControl::ConnectionFlowController.new(
      receive_window: 1_000_000, send_window: 30_000
    )
    stream_controller = Raiha::Quic::FlowControl::StreamFlowController.new(
      stream_id: Raiha::Quic::Protocol::StreamID.new(0),
      receive_window: 100_000,
      send_window: 100_000,
      connection_flow_controller: small_connection
    )
    assert_equal 30_000, stream_controller.send_window_size
  end

  def test_add_bytes_sent_updates_connection
    @stream_controller.add_bytes_sent(500)
    assert_equal 99_500, @stream_controller.send_window_size
    assert_equal 999_500, @connection_controller.send_window_size
  end

  def test_receive_window_exceeded
    assert_raises(Raiha::Quic::Qerr::FlowControlError) do
      @stream_controller.update_highest_received(0, 200_000)
    end
  end

  def test_final_size
    @stream_controller.set_final_size(5000)
    assert @stream_controller.has_final_size?
  end

  def test_final_size_changed_raises
    @stream_controller.set_final_size(5000)
    assert_raises(Raiha::Quic::Qerr::FinalSizeError) do
      @stream_controller.set_final_size(6000)
    end
  end

  def test_final_size_less_than_received_raises
    @stream_controller.update_highest_received(0, 5000)
    assert_raises(Raiha::Quic::Qerr::FinalSizeError) do
      @stream_controller.set_final_size(3000)
    end
  end

  def test_fully_received
    @stream_controller.update_highest_received(0, 5000)
    @stream_controller.set_final_size(5000)
    assert @stream_controller.fully_received?
  end

  def test_not_fully_received
    @stream_controller.update_highest_received(0, 3000)
    @stream_controller.set_final_size(5000)
    refute @stream_controller.fully_received?
  end

  def test_window_update_advances_with_received_data_even_when_unread
    # 76 KB received, nothing read by the application yet — should still
    # cross the 25 % threshold (initial 100_000 * 0.25 = 25_000) and
    # advertise 100_000 fresh credit on top of highest_received.
    @stream_controller.update_highest_received(0, 76_000)
    assert @stream_controller.should_send_window_update?
    assert_equal 0, @stream_controller.bytes_read

    new_window = @stream_controller.get_window_update
    assert_equal 76_000 + 100_000, new_window
    refute @stream_controller.should_send_window_update?
  end

  def test_window_update_keeps_growing_across_repeated_advances
    @stream_controller.update_highest_received(0, 80_000)
    @stream_controller.get_window_update # ~ 180_000
    @stream_controller.update_highest_received(80_000, 80_000) # 160_000 total
    assert @stream_controller.should_send_window_update?
    assert_equal 160_000 + 100_000, @stream_controller.get_window_update
  end
end
