require "test_helper"
require "support/http3_pair"

# A client's requests and their responses: interim responses before the
# response, content, trailers, and the checks a response must pass.
class RaihaHTTP3ConnectionClientTest < Minitest::Test
  include HTTP3Pair

  Frame = HTTP3::Frame
  QPACK = HTTP3::QPACK
  GET = [[":method", "GET"], [":scheme", "https"], [":authority", "example.com"], [":path", "/"]].freeze
  OK = [[":status", "200"]].freeze

  def client
    client = HTTP3::Connection.client
    client.start(**CLIENT_STREAMS)
    sent(client)
    actions(client)
    client
  end

  def events(connection) = [].tap { |all| connection.each_event { all << _1 } }

  def headers(fields) = Frame.encode(Frame::Headers.new(field_section: QPACK::Encoder.new.encode(0, fields.map { QPACK::Field.new(name: _1, value: _2) })))

  def data(bytes) = Frame.encode(Frame::Data.new(data: bytes))

  def closed_with(connection) = actions(connection).grep(HTTP3::Action::Close).first&.error_code

  def stopped(code) = [HTTP3::Action::StopSending.new(stream_id: 0, error_code: code), HTTP3::Action::Reset.new(stream_id: 0, error_code: code)]

  def test_a_request_and_its_response
    client = client()
    client.send_request(0, GET, fin: true)
    bytes, fin = sent(client).fetch(0)
    assert_equal headers(GET), bytes
    assert fin
    client.stream_data(0, headers(OK) + data("hi"), fin: true)
    assert_equal [HTTP3::Event::Headers.new(stream_id: 0, headers: OK, fin: false), HTTP3::Event::Data.new(stream_id: 0, data: "hi", fin: true)], events(client)
  end

  def test_content_of_a_request
    client = client()
    post = [[":method", "POST"], *GET.drop(1)]
    client.send_request(0, post)
    assert_equal 4, client.send_data(0, "body", fin: true)
    bytes, fin = sent(client).fetch(0)
    assert_equal headers(post) + data("body"), bytes
    assert fin
  end

  def test_interim_responses_come_first
    client = client()
    client.send_request(0, GET, fin: true)
    client.stream_data(0, headers([[":status", "103"], ["link", "</a.css>"]]) + headers(OK) + headers([["x-checksum", "1"]]), fin: true)
    assert_equal [
      HTTP3::Event::Headers.new(stream_id: 0, headers: [[":status", "103"], ["link", "</a.css>"]], fin: false),
      HTTP3::Event::Headers.new(stream_id: 0, headers: OK, fin: false), HTTP3::Event::Trailers.new(stream_id: 0, headers: [["x-checksum", "1"]])
    ], events(client)
  end

  # RFC 9114 "Malformed Requests and Responses": a response that never has
  # content may say a Content-Length all the same.
  def test_responses_that_never_have_content
    client = client()
    client.send_request(0, [[":method", "HEAD"], *GET.drop(1)], fin: true)
    client.stream_data(0, headers(OK + [["content-length", "100"]]), fin: true)
    client.send_request(4, GET, fin: true)
    client.stream_data(4, headers([[":status", "304"], ["content-length", "100"]]), fin: true)
    assert_empty actions(client)
    client.send_request(8, GET, fin: true)
    client.stream_data(8, headers(OK + [["content-length", "100"]]), fin: true)
    assert_equal [HTTP3::Action::StopSending, HTTP3::Action::Reset], actions(client).map(&:class)
  end

  def test_malformed_responses
    [headers([["content-type", "text/plain"]]), headers([[":status", "200"], [":path", "/"]])].each do |bytes|
      client = client()
      client.send_request(0, GET, fin: true)
      client.stream_data(0, bytes)
      assert_equal stopped(HTTP3::ErrorCode::MESSAGE_ERROR), actions(client)
      assert_equal [HTTP3::Event::Reset.new(stream_id: 0, error_code: HTTP3::ErrorCode::MESSAGE_ERROR)], events(client)
    end
    client = client()
    client.send_request(0, GET, fin: true)
    client.stream_data(0, "".b, fin: true)
    assert_equal stopped(HTTP3::ErrorCode::MESSAGE_ERROR), actions(client)
  end

  # A client resets a response past its limit with H3_EXCESSIVE_LOAD, and
  # the application hears of it.
  def test_a_response_too_large
    [headers(OK + [["x-large", "x" * 100]]), Frame.encode(Frame::Headers.new(field_section: "\x00" * 401))].each do |bytes|
      client = HTTP3::Connection.client(settings: HTTP3::Settings.new(max_field_section_size: 100))
      client.send_request(0, GET, fin: true)
      client.stream_data(0, bytes)
      assert_equal stopped(HTTP3::ErrorCode::EXCESSIVE_LOAD), actions(client)
      assert_equal [HTTP3::Event::Reset.new(stream_id: 0, error_code: HTTP3::ErrorCode::EXCESSIVE_LOAD)], events(client)
    end
  end

  # This end allows no push (RFC 9114 "PUSH_PROMISE").
  def test_a_push_promise
    client = client()
    client.send_request(0, GET, fin: true)
    client.stream_data(0, Frame.encode(Frame::PushPromise.new(push_id: 0, field_section: "\x00\x00")))
    assert_equal HTTP3::ErrorCode::ID_ERROR, closed_with(client)
  end

  def test_bytes_on_a_stream_with_no_request
    client = client()
    client.stream_data(4, headers(OK))
    assert_empty events(client)
    assert_empty actions(client)
  end

  def test_misuse
    client = client()
    assert_raises(ArgumentError) { client.send_request(2, GET) }
    assert_raises(ArgumentError) { client.send_request(0, GET.drop(1)) }
    assert_raises(ArgumentError) { client.send_request(0, [[":method", "CONNECT"], [":protocol", "websocket"], *GET.drop(1)]) }
    client.send_request(0, GET)
    assert_raises(HTTP3::Error::Usage) { client.send_request(0, GET) }
    assert_raises(HTTP3::Error::Usage) { HTTP3::Connection.server.send_request(0, GET) }
  end
end
