require "test_helper"
require "support/http3_pair"

# The Capsule Protocol on Extended CONNECT (RFC 9297, RFC 9220): the data
# stream carries Capsules, DATAGRAM ones being HTTP Datagrams.
class RaihaHTTP3ConnectionCapsuleTest < Minitest::Test
  include HTTP3Pair

  Frame = HTTP3::Frame
  QPACK = HTTP3::QPACK
  Capsule = HTTP3::Capsule
  CONNECT = [
    [":method", "CONNECT"], [":protocol", "connect-udp"], [":scheme", "https"], [":authority", "proxy.example"], [":path", "/udp"],
    ["capsule-protocol", "?1"]
  ].freeze

  def events(connection) = [].tap { |all| connection.each_event { all << _1 } }

  def headers(fields) = Frame.encode(Frame::Headers.new(field_section: QPACK::Encoder.new.encode(0, fields.map { QPACK::Field.new(name: _1, value: _2) })))

  def data(bytes) = Frame.encode(Frame::Data.new(data: bytes))

  def capsules(*capsules) = capsules.map { Capsule.encode(_1) }.join

  def server(request = CONNECT)
    server = HTTP3::Connection.server
    server.start(**SERVER_STREAMS)
    sent(server)
    actions(server)
    server.stream_data(0, headers(request))
    events(server)
    server
  end

  def test_capsules_of_a_request
    server = server()
    bytes = capsules(Capsule.new(type: 0, value: "ping"), Capsule.new(type: 0x2028d7ee, value: "address"))
    server.stream_data(0, data(bytes.byteslice(0, 3)) + data(bytes.byteslice(3..)))
    assert_equal [HTTP3::Event::Datagram.new(stream_id: 0, payload: "ping"), HTTP3::Event::Capsule.new(stream_id: 0, capsule: Capsule.new(type: 0x2028d7ee, value: "address"))], events(server)
  end

  # RFC 9297 "Error Handling": a Capsule cut short by the end of the
  # stream makes the message malformed.
  def test_a_capsule_cut_short
    server = server()
    server.stream_data(0, data("\x00\x05ab"), fin: true)
    assert_equal [HTTP3::Action::StopSending, HTTP3::Action::Reset], actions(server).map(&:class)
    assert_equal [HTTP3::Event::Reset.new(stream_id: 0, error_code: HTTP3::ErrorCode::MESSAGE_ERROR)], events(server)
  end

  def test_the_capsule_protocol_with_content
    server = HTTP3::Connection.server
    server.stream_data(0, headers(CONNECT + [["content-type", "application/octet-stream"]]))
    assert_equal [HTTP3::Action::StopSending, HTTP3::Action::Reset], actions(server).map(&:class)
  end

  # Only Extended CONNECT uses it; any other request's DATA is content.
  def test_no_capsules_for_other_requests
    get = [[":method", "POST"], [":scheme", "https"], [":authority", "a"], [":path", "/"], ["capsule-protocol", "?1"]]
    server = server(get)
    server.stream_data(0, data(capsules(Capsule.new(type: 0, value: "x"))))
    assert_equal [HTTP3::Event::Data.new(stream_id: 0, data: "\x00\x01x", fin: false)], events(server)
  end

  def test_sending_capsules
    server = server()
    capsule = Capsule.new(type: 0, value: "pong")
    assert_raises(HTTP3::Error::Usage) { server.send_capsule(0, capsule) }
    server.send_headers(0, [[":status", "200"], ["capsule-protocol", "?1"]])
    sent(server)
    assert server.send_capsule(0, capsule)
    assert_equal data(Capsule.encode(capsule)), sent(server).fetch(0).first
    other = server(CONNECT.reject { _1.first == "capsule-protocol" })
    other.send_headers(0, [[":status", "200"]])
    assert_raises(HTTP3::Error::Usage) { other.send_capsule(0, capsule) }
  end

  def test_a_capsule_waits_for_room
    server = HTTP3::Connection.server(max_send_buffer: 10)
    server.start(**SERVER_STREAMS)
    server.stream_data(0, headers(CONNECT))
    server.send_headers(0, [[":status", "200"]])
    sent(server)
    events(server)
    refute server.send_capsule(0, Capsule.new(type: 0, value: "x" * 20))
    assert server.send_capsule(0, Capsule.new(type: 0, value: "x" * 5))
    sent(server)
    assert_equal [HTTP3::Event::Writable.new(stream_id: 0)], events(server)
  end

  # A client reads Capsules once the response is a 2xx.
  def test_a_client
    client = HTTP3::Connection.client
    client.stream_data(3, "\x00".b + Frame.encode(HTTP3::Settings.new(enable_connect_protocol: true).to_frame))
    events(client)
    client.send_request(0, CONNECT)
    client.stream_data(0, headers([[":status", "200"], ["capsule-protocol", "?1"]]) + data(capsules(Capsule.new(type: 0, value: "hi"))))
    assert_equal [HTTP3::Event::Headers, HTTP3::Event::Datagram], events(client).map(&:class)
    client.send_request(4, CONNECT)
    client.stream_data(4, headers([[":status", "204"], ["capsule-protocol", "?1"]]))
    assert_equal [HTTP3::Event::Reset.new(stream_id: 4, error_code: HTTP3::ErrorCode::MESSAGE_ERROR)], events(client)
  end
end
