require "test_helper"
require "raiha/stream"
require "raiha/quic/flow_control"
require "raiha/quic/protocol/stream_id"

class RaihaStreamTest < Minitest::Test
  def test_write_and_get_data_to_send
    stream = create_stream(send_window: 10000)

    stream.write("hello world".b)
    result = stream.get_data_to_send(1024)

    refute_nil result
    assert_equal 0, result[:offset]
    assert_equal "hello world".b, result[:data]
    refute result[:fin]
  end

  def test_write_with_fin
    stream = create_stream(send_window: 10000)

    stream.write("data".b)
    stream.close_write
    result = stream.get_data_to_send(1024)

    assert result[:fin]
    assert_equal Raiha::Stream::SendState::DATA_SENT, stream.send_state
  end

  def test_receive_data_and_read
    stream = create_stream

    stream.receive_data(0, "hello".b)
    assert stream.data_available?

    data = stream.read
    assert_equal "hello".b, data
  end

  def test_receive_data_with_fin
    stream = create_stream

    stream.receive_data(0, "complete".b, fin: true)
    assert_equal Raiha::Stream::ReceiveState::SIZE_KNOWN, stream.receive_state

    data = stream.read
    assert_equal "complete".b, data
    assert_equal Raiha::Stream::ReceiveState::DATA_READ, stream.receive_state
  end

  def test_receive_out_of_order
    stream = create_stream

    stream.receive_data(5, "world".b)
    refute stream.data_available? # offset 0 not yet received

    stream.receive_data(0, "hello".b)
    assert stream.data_available?

    data = stream.read
    assert_equal "helloworld".b, data
  end

  def test_writable_state
    stream = create_stream(send_window: 10000)

    assert stream.writable?
    stream.write("data".b)
    assert stream.writable?
    stream.close_write
    refute stream.writable?
  end

  def test_readable_state
    stream = create_stream
    assert stream.readable?
  end

  def test_flow_control_limit
    stream = create_stream(send_window: 5)

    stream.write("hello world".b)
    result = stream.get_data_to_send(1024)

    assert_equal 5, result[:data].bytesize
  end

  def test_on_data_callback
    stream = create_stream
    callback_called = false

    stream.on_data { |_stream| callback_called = true }
    stream.receive_data(0, "data".b)

    assert callback_called
  end

  private def create_stream(send_window: 0, receive_window: 100000)
    connection_flow_controller = Raiha::Quic::FlowControl::ConnectionFlowController.new(
      receive_window: 1_000_000, send_window: 1_000_000
    )
    flow_controller = Raiha::Quic::FlowControl::StreamFlowController.new(
      stream_id: Raiha::Quic::Protocol::StreamID.new(0),
      receive_window: receive_window,
      send_window: send_window,
      connection_flow_controller: connection_flow_controller
    )
    Raiha::Stream.new(
      stream_id: Raiha::Quic::Protocol::StreamID.new(0),
      flow_controller: flow_controller
    )
  end
end
