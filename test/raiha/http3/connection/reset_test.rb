require "test_helper"
require "support/http3_pair"

# Request streams stopped part of the way (RFC 9114 "Request Cancellation
# and Rejection"): the peer resetting what it sends, the peer stopping
# what this end sends, and either end cancelling both.
class RaihaHTTP3ConnectionResetTest < Minitest::Test
  include HTTP3Pair

  Frame = HTTP3::Frame
  QPACK = HTTP3::QPACK
  POST = [[":method", "POST"], [":scheme", "https"], [":authority", "example.com"], [":path", "/"]].freeze
  CANCELLED = HTTP3::ErrorCode::REQUEST_CANCELLED

  def server(**settings)
    server = HTTP3::Connection.server(settings: HTTP3::Settings.new(**settings))
    server.start(**SERVER_STREAMS)
    sent(server)
    actions(server)
    server
  end

  def events(connection) = [].tap { |all| connection.each_event { all << _1 } }

  def headers(fields) = Frame.encode(Frame::Headers.new(field_section: QPACK::Encoder.new.encode(0, fields.map { QPACK::Field.new(name: _1, value: _2) })))

  def data(bytes) = Frame.encode(Frame::Data.new(data: bytes))

  # A server with the request on stream 0 taken.
  def with_request
    server = server()
    server.stream_data(0, headers(POST))
    events(server)
    server
  end

  # The peer's side ends; the application hears, and may still answer.
  def test_the_peer_resets_its_side
    server = with_request
    server.stream_reset(0, error_code: CANCELLED)
    assert_equal [HTTP3::Event::Reset.new(stream_id: 0, error_code: CANCELLED)], events(server)
    server.stream_data(0, data("late"))
    assert_empty events(server)
    server.send_headers(0, [[":status", "200"]], fin: true)
    assert sent(server).fetch(0).last
  end

  # A request the application never had ends with no event; its section
  # waiting on QPACK is cancelled.
  def test_the_peer_resets_a_request_not_taken
    server = server(qpack_max_table_capacity: 4096, qpack_blocked_streams: 1)
    server.stream_data(0, Frame.encode(Frame::Headers.new(field_section: "\x02\x00\x80".b)))
    events(server)
    server.stream_reset(0, error_code: CANCELLED)
    assert_empty events(server)
    assert_equal({ 11 => ["\x40".b, false] }, sent(server))
  end

  # Nothing more goes; the peer's side still comes.
  def test_the_peer_stops_this_ends_side
    server = with_request
    server.send_headers(0, [[":status", "200"]])
    server.stream_stopped(0, error_code: CANCELLED)
    assert_equal [HTTP3::Event::Stopped.new(stream_id: 0, error_code: CANCELLED)], events(server)
    assert_empty sent(server)
    assert_raises(HTTP3::Error::Usage) { server.send_data(0, "more") }
    server.stream_data(0, data("body"), fin: true)
    assert_equal [HTTP3::Event::Data.new(stream_id: 0, data: "body", fin: true)], events(server)
  end

  def test_the_peer_stops_a_stream_done_sending
    server = with_request
    server.send_headers(0, [[":status", "204"]], fin: true)
    server.stream_stopped(0, error_code: CANCELLED)
    assert_empty events(server)
  end

  def test_cancelling
    server = with_request
    server.cancel(0)
    assert_equal [HTTP3::Action::StopSending.new(stream_id: 0, error_code: CANCELLED), HTTP3::Action::Reset.new(stream_id: 0, error_code: CANCELLED)], actions(server)
    server.stream_data(0, data("late"))
    assert_empty events(server)
    assert_raises(HTTP3::Error::Usage) { server.send_headers(0, [[":status", "200"]]) }
    server.cancel(0)
    server.cancel(4)
    assert_empty actions(server)
    assert_raises(ArgumentError) { server.cancel(2) }
    assert_raises(ArgumentError) { server.cancel(0, error_code: -1) }
  end

  # A server that needs no more of a request asks for no more, and
  # answers it still.
  def test_stopping_reading
    server = with_request
    server.stop_reading(0)
    assert_equal [HTTP3::Action::StopSending.new(stream_id: 0, error_code: HTTP3::ErrorCode::NO_ERROR)], actions(server)
    server.stream_data(0, data("late"), fin: true)
    assert_empty events(server)
    server.send_headers(0, [[":status", "200"]], fin: true)
    assert sent(server).fetch(0).last
    server.stop_reading(0)
    server.stop_reading(4)
    assert_empty actions(server)
    assert_raises(ArgumentError) { server.stop_reading(2) }
    assert_raises(HTTP3::Error::Usage) { HTTP3::Connection.client.stop_reading(0) }
  end

  # A request that has come whole has nothing more to stop.
  def test_stopping_reading_a_request_that_ended
    server = server()
    server.stream_data(0, headers(POST) + data("body"), fin: true)
    events(server)
    server.stop_reading(0)
    assert_empty actions(server)
  end

  def test_a_client_cancels_its_request
    client = HTTP3::Connection.client
    client.send_request(0, POST)
    client.cancel(0, error_code: HTTP3::ErrorCode::NO_ERROR)
    assert_equal [HTTP3::Action::StopSending, HTTP3::Action::Reset], actions(client).grep_v(HTTP3::Action::Priority).map(&:class)
    client.stream_data(0, headers([[":status", "200"]]))
    assert_empty events(client)
  end

  # Once the connection is closed, there is nothing to write to.
  def test_nothing_to_write_to_after_closing
    server = with_request
    server.stream_data(2, "\x01".b)
    assert server.closed?
    assert_raises(HTTP3::Error::Usage) { server.send_headers(0, [[":status", "200"]]) }
  end
end
