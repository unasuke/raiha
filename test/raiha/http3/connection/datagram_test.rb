require "test_helper"
require "support/http3_pair"

# HTTP Datagrams (RFC 9297 "HTTP/3 Datagrams"): a Quarter Stream ID and a
# payload, only for requests that have a use for them, only once both
# ends took them.
class RaihaNextHTTP3ConnectionDatagramTest < Minitest::Test
  include NextHTTP3Pair

  Frame = HTTP3::Frame
  QPACK = HTTP3::QPACK
  CONNECT = [[":method", "CONNECT"], [":protocol", "connect-udp"], [":scheme", "https"], [":authority", "proxy.example"], [":path", "/udp"]].freeze
  GET = [[":method", "GET"], [":scheme", "https"], [":authority", "example.com"], [":path", "/"]].freeze

  def events(connection) = [].tap { |all| connection.each_event { all << _1 } }

  def headers(fields, stream_id: 0) = Frame.encode(Frame::Headers.new(field_section: QPACK::Encoder.new.encode(stream_id, fields.map { QPACK::Field.new(name: _1, value: _2) })))

  def closed_with(connection) = actions(connection).grep(HTTP3::Action::Close).first&.error_code

  def datagrams(connection) = [].tap { |all| connection.each_datagram_send { |data, urgency| all << [data, urgency] } }

  # A server with Extended CONNECT on stream 0 and a GET on stream 4, the
  # client's SETTINGS taken; both ends take HTTP Datagrams.
  def server(settings: HTTP3::Settings.new(enable_connect_protocol: true, h3_datagram: true), peer: HTTP3::Settings.new(h3_datagram: true))
    server = HTTP3::Connection.server(settings:)
    server.start(**SERVER_STREAMS)
    server.stream_data(2, "\x00".b + Frame.encode(peer.to_frame))
    server.stream_data(0, headers(CONNECT))
    server.stream_data(4, headers(GET, stream_id: 4))
    sent(server)
    actions(server)
    events(server)
    server.datagram_max_size = -> { 1000 }
    server
  end

  def test_a_datagram_each_way
    server = server()
    server.datagram_received("\x00ping".b)
    assert_equal [HTTP3::Event::Datagram.new(stream_id: 0, payload: "ping")], events(server)
    assert server.datagram_send(0, "pong")
    assert_equal [["\x00pong".b, 3]], datagrams(server)
    assert_empty datagrams(server)
  end

  # RFC 9297: dropped for a stream not open yet or done receiving; the
  # request stopped with H3_DATAGRAM_ERROR when it has no use for them.
  def test_datagrams_received_for_other_streams
    server = server()
    server.datagram_received("\x02x".b)
    assert_empty events(server)
    server.datagram_received("\x01x".b)
    code = HTTP3::ErrorCode::DATAGRAM_ERROR
    assert_equal [HTTP3::Action::StopSending.new(stream_id: 4, error_code: code), HTTP3::Action::Reset.new(stream_id: 4, error_code: code)], actions(server)
    assert_equal [HTTP3::Event::Reset.new(stream_id: 4, error_code: code)], events(server)
    server.stream_data(0, "".b, fin: true)
    events(server)
    server.datagram_received("\x00late".b)
    assert_empty events(server)
    refute server.closed?
  end

  def test_datagrams_that_do_not_hold
    ["".b, "\x40".b, "\xd0\x00\x00\x00\x00\x00\x00\x00".b].each do |bytes|
      server = server()
      server.datagram_received(bytes)
      assert_equal HTTP3::ErrorCode::DATAGRAM_ERROR, closed_with(server), bytes.inspect
    end
  end

  def test_none_taken_when_this_end_said_so
    server = server(settings: HTTP3::Settings.new(enable_connect_protocol: true))
    server.datagram_received("\x00ping".b)
    assert_empty events(server)
    refute server.datagram_send(0, "pong")
  end

  # Sent only once the peer took them too, on a request with a use for
  # them, that fits, and while few enough wait.
  def test_what_goes
    refute server(peer: HTTP3::Settings.new).datagram_send(0, "x")
    server = server()
    refute server.datagram_send(4, "x")
    refute server.datagram_send(8, "x")
    refute server.datagram_send(0, "x" * 1000)
    assert server.datagram_send(0, "x" * 999)
    server.datagram_max_size = -> {}
    refute server.datagram_send(0, "x")
    server.datagram_max_size = -> { 1000 }
    (HTTP3::Connection::MAX_DATAGRAMS - 1).times { assert server.datagram_send(0, "x") }
    refute server.datagram_send(0, "x")
  end

  # The urgency of the request goes with its datagrams.
  def test_the_urgency_of_the_request
    server = server()
    server.update_priority(0, urgency: 1, incremental: true)
    server.datagram_send(0, "x")
    assert_equal [["\x00x".b, 1]], datagrams(server)
  end
end
