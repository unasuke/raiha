require "test_helper"
require "raiha/streams_map"

class RaihaStreamsMapTest < Minitest::Test
  def test_get_or_create_stream
    streams_map = create_streams_map(max_streams_bidi: 10)

    stream = streams_map.get_or_create_stream(1) # Server-initiated bidi
    refute_nil stream
    assert_equal 1, stream.stream_id.value
    assert_equal 1, streams_map.active_streams_count
  end

  def test_get_or_create_returns_same_stream
    streams_map = create_streams_map(max_streams_bidi: 10)

    stream1 = streams_map.get_or_create_stream(0)
    stream2 = streams_map.get_or_create_stream(0)
    assert_same stream1, stream2
    assert_equal 1, streams_map.active_streams_count
  end

  def test_open_bidirectional_stream
    streams_map = create_streams_map
    streams_map.update_peer_max_streams_bidi(10)

    stream = streams_map.open_bidirectional_stream
    refute_nil stream
    assert_equal 0, stream.stream_id.value # Client-initiated bidi
  end

  def test_open_sequential_bidi_streams
    streams_map = create_streams_map
    streams_map.update_peer_max_streams_bidi(10)

    stream1 = streams_map.open_bidirectional_stream
    stream2 = streams_map.open_bidirectional_stream
    assert_equal 0, stream1.stream_id.value
    assert_equal 4, stream2.stream_id.value
  end

  def test_open_unidirectional_stream
    streams_map = create_streams_map
    streams_map.update_peer_max_streams_uni(10)

    stream = streams_map.open_unidirectional_stream
    assert_equal 2, stream.stream_id.value # Client-initiated uni
  end

  def test_accept_stream_nonblock_returns_nil_when_empty
    streams_map = create_streams_map
    assert_nil streams_map.accept_stream_nonblock
  end

  def test_accept_stream_nonblock_returns_incoming
    streams_map = create_streams_map(max_streams_bidi: 10)

    streams_map.get_or_create_stream(1) # Incoming server-initiated bidi
    stream = streams_map.accept_stream_nonblock

    refute_nil stream
    assert_equal 1, stream.stream_id.value
  end

  def test_stream_limit_exceeded
    streams_map = create_streams_map(max_streams_bidi: 1)

    streams_map.get_or_create_stream(0) # First stream OK
    assert_raises(Raiha::Quic::Qerr::StreamLimitError) do
      streams_map.get_or_create_stream(4) # Second stream exceeds limit
    end
  end

  def test_server_perspective
    connection_flow_controller = Raiha::Quic::FlowControl::ConnectionFlowController.new(
      receive_window: 1_000_000, send_window: 1_000_000
    )
    streams_map = Raiha::StreamsMap.new(
      perspective: :server,
      connection_flow_controller: connection_flow_controller,
      max_streams_bidi: 10
    )
    streams_map.update_peer_max_streams_bidi(10)

    stream = streams_map.open_bidirectional_stream
    assert_equal 1, stream.stream_id.value # Server-initiated bidi
  end

  private def create_streams_map(max_streams_bidi: 0, max_streams_uni: 0)
    connection_flow_controller = Raiha::Quic::FlowControl::ConnectionFlowController.new(
      receive_window: 1_000_000, send_window: 1_000_000
    )
    Raiha::StreamsMap.new(
      perspective: :client,
      connection_flow_controller: connection_flow_controller,
      max_streams_bidi: max_streams_bidi,
      max_streams_uni: max_streams_uni
    )
  end
end
