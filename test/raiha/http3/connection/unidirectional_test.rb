require "test_helper"
require "support/http3_pair"

# The peer's streams going one way (RFC 9114 "Unidirectional Streams",
# RFC 9204 "Encoder and Decoder Streams"): one each of the control and
# QPACK streams, never closed; no push; a type not known passed over.
class RaihaNextHTTP3ConnectionUnidirectionalTest < Minitest::Test
  include NextHTTP3Pair

  def server
    server = HTTP3::Connection.server
    server.start(**SERVER_STREAMS)
    sent(server)
    actions(server)
    server
  end

  # The client's control and QPACK streams, on `connection`.
  def open_the_clients(connection)
    connection.stream_data(2, "\x00".b + HTTP3::Frame.encode(HTTP3::Settings.new.to_frame))
    connection.stream_data(6, "\x02".b)
    connection.stream_data(10, "\x03".b)
  end

  # The one Action `connection` asks for: a Close with `code`.
  def assert_closed_with(code, connection)
    asked = actions(connection)
    assert_equal [HTTP3::Action::Close], asked.map(&:class), asked.inspect
    assert_equal code, asked.first.error_code
    assert connection.closed?
  end

  def test_the_peers_streams
    server = server()
    open_the_clients(server)
    assert_empty actions(server)
    refute server.closed?
  end

  def test_a_second_stream_of_a_type
    [["\x00", 14], ["\x02", 14], ["\x03", 14]].each do |type, stream_id|
      server = server()
      open_the_clients(server)
      server.stream_data(stream_id, type.b)
      assert_closed_with HTTP3::ErrorCode::STREAM_CREATION_ERROR, server
    end
  end

  # A type not known, among them those reserved to be ignored, is passed
  # over with STOP_SENDING; its type may come a byte at a time.
  def test_a_type_not_known
    server = server()
    server.stream_data(14, "\x40".b)
    assert_empty actions(server)
    server.stream_data(14, "\x21junk".b)
    assert_equal [HTTP3::Action::StopSending.new(stream_id: 14, error_code: HTTP3::ErrorCode::STREAM_CREATION_ERROR)], actions(server)
    server.stream_data(14, "more".b, fin: true)
    server.stream_data(18, "\x3f".b)
    assert_equal [HTTP3::Action::StopSending.new(stream_id: 18, error_code: HTTP3::ErrorCode::STREAM_CREATION_ERROR)], actions(server)
    refute server.closed?
  end

  # This end allows no push: a client's push stream is never allowed, and
  # a server's needs a push ID the client never gave.
  def test_push_streams
    server = server()
    server.stream_data(2, "\x01".b)
    assert_closed_with HTTP3::ErrorCode::STREAM_CREATION_ERROR, server
    client = HTTP3::Connection.client
    client.stream_data(3, "\x01\x00".b)
    assert_closed_with HTTP3::ErrorCode::ID_ERROR, client
  end

  def test_the_peer_closes_a_critical_stream
    server = server()
    open_the_clients(server)
    server.stream_data(2, "".b, fin: true)
    assert_closed_with HTTP3::ErrorCode::CLOSED_CRITICAL_STREAM, server
    server = server()
    open_the_clients(server)
    server.stream_reset(6, error_code: 0)
    assert_closed_with HTTP3::ErrorCode::CLOSED_CRITICAL_STREAM, server
  end

  def test_the_peer_stops_a_critical_stream_of_this_end
    server = server()
    server.stream_stopped(7, error_code: 0)
    assert_closed_with HTTP3::ErrorCode::CLOSED_CRITICAL_STREAM, server
  end

  # RFC 9114 "Unidirectional Streams": a stream may end before its type.
  def test_a_stream_ended_before_its_type
    server = server()
    server.stream_data(14, "".b, fin: true)
    server.stream_data(18, "\x80".b)
    server.stream_reset(18, error_code: 0)
    assert_empty actions(server)
  end

  def test_nothing_after_closing
    server = server()
    server.stream_data(2, "\x01".b)
    actions(server)
    server.stream_data(6, "\x02".b)
    server.stream_data(14, "\x02".b)
    server.stream_reset(6, error_code: 0)
    assert_empty actions(server)
    assert_empty sent(server)
  end

  def test_this_ends_streams_are_not_the_peers
    assert_raises(ArgumentError) { server.stream_data(3, "x".b) }
  end
end
