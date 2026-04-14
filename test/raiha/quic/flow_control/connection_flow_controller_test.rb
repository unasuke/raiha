require "test_helper"
require "raiha/quic/flow_control"

class RaihaQuicFlowControlConnectionFlowControllerTest < Minitest::Test
  def test_send_window_size
    controller = Raiha::Quic::FlowControl::ConnectionFlowController.new(
      receive_window: 100_000, send_window: 50_000
    )
    assert_equal 50_000, controller.send_window_size
  end

  def test_add_bytes_sent
    controller = Raiha::Quic::FlowControl::ConnectionFlowController.new(
      receive_window: 100_000, send_window: 1000
    )
    controller.add_bytes_sent(500)
    assert_equal 500, controller.send_window_size
  end

  def test_send_window_exceeded
    controller = Raiha::Quic::FlowControl::ConnectionFlowController.new(
      receive_window: 100_000, send_window: 100
    )
    assert_raises(Raiha::Quic::Qerr::FlowControlError) do
      controller.add_bytes_sent(200)
    end
  end

  def test_receive_window_exceeded
    controller = Raiha::Quic::FlowControl::ConnectionFlowController.new(
      receive_window: 1000, send_window: 0
    )
    assert_raises(Raiha::Quic::Qerr::FlowControlError) do
      controller.update_highest_received(2000)
    end
  end

  def test_update_send_window
    controller = Raiha::Quic::FlowControl::ConnectionFlowController.new(
      receive_window: 100_000, send_window: 100
    )
    controller.update_send_window(500)
    assert_equal 500, controller.send_window_size
  end

  def test_can_send
    controller = Raiha::Quic::FlowControl::ConnectionFlowController.new(
      receive_window: 100_000, send_window: 100
    )
    assert controller.can_send?(100)
    refute controller.can_send?(101)
  end
end
