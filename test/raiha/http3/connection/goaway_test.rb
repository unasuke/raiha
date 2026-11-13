require "test_helper"
require "support/http3_pair"

# GOAWAY (RFC 9114 "Connection Shutdown") both ways, and the frames of
# push, which this end never uses.
class RaihaHTTP3ConnectionGoAwayTest < Minitest::Test
  include HTTP3Pair

  Frame = HTTP3::Frame
  QPACK = HTTP3::QPACK
  GET = [[":method", "GET"], [":scheme", "https"], [":authority", "example.com"], [":path", "/"]].freeze
  SETTINGS = Frame.encode(HTTP3::Settings.new.to_frame)

  def events(connection) = [].tap { |all| connection.each_event { all << _1 } }

  def closed_with(connection) = actions(connection).grep(HTTP3::Action::Close).first&.error_code

  def headers(fields, stream_id: 0) = Frame.encode(Frame::Headers.new(field_section: QPACK::Encoder.new.encode(stream_id, fields.map { QPACK::Field.new(name: _1, value: _2) })))

  def started(connection, streams)
    connection.start(**streams)
    sent(connection)
    actions(connection)
    connection
  end

  # The peer's control stream, its SETTINGS and then `frames`.
  def control(connection, *frames, stream_id:)
    connection.stream_data(stream_id, "\x00".b + SETTINGS + frames.map { Frame.encode(_1) }.join)
  end

  # The requests from the ID given on were not processed: the client lets
  # them go, hears each was rejected, and makes no more.
  def test_a_client_told_the_server_goes_away
    client = started(HTTP3::Connection.client, CLIENT_STREAMS)
    [0, 4, 8].each { |stream_id| client.send_request(stream_id, GET, fin: true) }
    sent(client)
    events(client)
    control(client, Frame::GoAway.new(id: 4), stream_id: 3)
    rejected = HTTP3::ErrorCode::REQUEST_REJECTED
    assert_equal [
      HTTP3::Event::Settings.new(settings: HTTP3::Settings.new), HTTP3::Event::GoAway.new(stream_id: 4),
      HTTP3::Event::Reset.new(stream_id: 4, error_code: rejected), HTTP3::Event::Reset.new(stream_id: 8, error_code: rejected)
    ], events(client)
    assert_equal [4, 4, 8, 8], actions(client).map(&:stream_id)
    assert_raises(HTTP3::Error::Usage) { client.send_request(12, GET) }
    client.stream_data(0, headers([[":status", "200"]]), fin: true)
    assert_equal [HTTP3::Event::Headers.new(stream_id: 0, headers: [[":status", "200"]], fin: true)], events(client)
  end

  def test_a_goaway_a_client_does_not_take
    [[Frame::GoAway.new(id: 2)], [Frame::GoAway.new(id: 4), Frame::GoAway.new(id: 8)]].each do |frames|
      client = HTTP3::Connection.client
      control(client, *frames, stream_id: 3)
      assert_equal HTTP3::ErrorCode::ID_ERROR, closed_with(client), frames.inspect
    end
    client = HTTP3::Connection.client
    control(client, Frame::GoAway.new(id: 8), Frame::GoAway.new(id: 8), Frame::GoAway.new(id: 0), stream_id: 3)
    assert_nil closed_with(client)
  end

  # A server's GOAWAY gives the first request it has not seen, and the
  # requests that come from there on are rejected; those before go on.
  def test_a_server_goes_away
    server = started(HTTP3::Connection.server, SERVER_STREAMS)
    [0, 4].each { |stream_id| server.stream_data(stream_id, headers(GET, stream_id:)) }
    events(server)
    server.goaway
    assert_equal "\x07\x01\x08".b, sent(server).fetch(3).first
    server.stream_data(8, headers(GET, stream_id: 8))
    rejected = HTTP3::ErrorCode::REQUEST_REJECTED
    assert_equal [HTTP3::Action::StopSending.new(stream_id: 8, error_code: rejected), HTTP3::Action::Reset.new(stream_id: 8, error_code: rejected)], actions(server)
    assert_empty events(server)
    server.send_headers(4, [[":status", "200"]], fin: true)
    assert_raises(ArgumentError) { server.goaway(12) }
    assert_raises(ArgumentError) { server.goaway(2) }
    server.goaway(4)
    assert_equal "\x07\x01\x04".b, sent(server).fetch(3).first
  end

  def test_a_client_goes_away
    assert_raises(HTTP3::Error::Usage) { HTTP3::Connection.client.goaway }
    client = started(HTTP3::Connection.client, CLIENT_STREAMS)
    client.goaway
    assert_equal "\x07\x01\x00".b, sent(client).fetch(2).first
  end

  # A client's GOAWAY gives a push ID, which may not grow either.
  def test_a_server_told_the_client_goes_away
    server = HTTP3::Connection.server
    control(server, Frame::GoAway.new(id: 3), stream_id: 2)
    assert_equal [HTTP3::Event::GoAway.new(stream_id: 3)], events(server).drop(1)
    server.stream_data(2, Frame.encode(Frame::GoAway.new(id: 4)))
    assert_equal HTTP3::ErrorCode::ID_ERROR, closed_with(server)
  end

  # This end allows and promises no push: CANCEL_PUSH has no push to
  # name; a client's MAX_PUSH_ID is taken, but may not shrink.
  def test_the_frames_of_push
    [[HTTP3::Connection.server, 2], [HTTP3::Connection.client, 3]].each do |connection, stream_id|
      control(connection, Frame::CancelPush.new(push_id: 0), stream_id:)
      assert_equal HTTP3::ErrorCode::ID_ERROR, closed_with(connection)
    end
    server = HTTP3::Connection.server
    control(server, Frame::MaxPushId.new(push_id: 4), Frame::MaxPushId.new(push_id: 4), Frame::MaxPushId.new(push_id: 9), stream_id: 2)
    assert_nil closed_with(server)
    server.stream_data(2, Frame.encode(Frame::MaxPushId.new(push_id: 8)))
    assert_equal HTTP3::ErrorCode::ID_ERROR, closed_with(server)
  end
end
