require "test_helper"
require "support/http3_pair"

# The content and trailers of requests (RFC 9114 "HTTP Message
# Framing"): DATA after the header section, a trailer section at most,
# the content counted against Content-Length, and the trailers against
# what the header section left of the limit.
class RaihaHTTP3ConnectionRequestBodyTest < Minitest::Test
  include HTTP3Pair

  Frame = HTTP3::Frame
  QPACK = HTTP3::QPACK
  POST = [[":method", "POST"], [":scheme", "https"], [":authority", "example.com"], [":path", "/upload"]].freeze

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

  def closed_with(connection) = actions(connection).grep(HTTP3::Action::Close).first&.error_code

  # The application had the request, and hears it was stopped with `code`.
  def assert_stopped(server, code, events)
    assert_equal [HTTP3::Action::StopSending.new(stream_id: 0, error_code: code), HTTP3::Action::Reset.new(stream_id: 0, error_code: code)], actions(server)
    assert_equal HTTP3::Event::Reset.new(stream_id: 0, error_code: code), events.last
    refute server.closed?
  end

  def test_content
    server = server()
    server.stream_data(0, headers(POST + [["content-length", "10"]]) + data("hello"))
    server.stream_data(0, data("") + data("world"), fin: true)
    assert_equal [
      HTTP3::Event::Headers.new(stream_id: 0, headers: POST + [["content-length", "10"]], fin: false),
      HTTP3::Event::Data.new(stream_id: 0, data: "hello", fin: false), HTTP3::Event::Data.new(stream_id: 0, data: "world", fin: true)
    ], events(server)
  end

  # The trailer section ends the message; nothing more comes for it.
  def test_trailers
    server = server()
    server.stream_data(0, headers(POST) + data("abc") + headers([["x-checksum", "1"]]) + "\x21\x00".b)
    server.stream_data(0, "".b, fin: true)
    assert_equal [
      HTTP3::Event::Headers.new(stream_id: 0, headers: POST, fin: false), HTTP3::Event::Data.new(stream_id: 0, data: "abc", fin: false),
      HTTP3::Event::Trailers.new(stream_id: 0, headers: [["x-checksum", "1"]])
    ], events(server)
    assert_empty actions(server)
  end

  def test_frames_after_the_trailers
    [data("late"), headers([["x-more", "1"]])].each do |frame|
      server = server()
      server.stream_data(0, headers(POST) + headers([["x-checksum", "1"]]) + frame)
      assert_equal HTTP3::ErrorCode::FRAME_UNEXPECTED, closed_with(server)
    end
  end

  # RFC 9114 "Malformed Requests and Responses": more content than
  # Content-Length, or less by the end or the trailers.
  def test_content_length
    [
      [headers(POST + [["content-length", "3"]]) + data("abcd"), false],
      [headers(POST + [["content-length", "5"]]) + data("abcd"), true],
      [headers(POST + [["content-length", "5"]]) + data("abcd") + headers([["x-checksum", "1"]]), false]
    ].each do |bytes, fin|
      server = server()
      server.stream_data(0, bytes, fin:)
      assert_stopped server, HTTP3::ErrorCode::MESSAGE_ERROR, events(server)
    end
  end

  def test_malformed_trailers
    server = server()
    server.stream_data(0, headers(POST) + headers([[":status", "200"]]))
    assert_stopped server, HTTP3::ErrorCode::MESSAGE_ERROR, events(server)
  end

  # More than MAX_EVENTS events left untaken close the connection with
  # H3_INTERNAL_ERROR; taken as they come, none do.
  def test_events_left_untaken
    pieces = data("x") * (HTTP3::Connection::MAX_EVENTS + 1)
    server = server()
    server.stream_data(0, headers(POST))
    events(server)
    server.stream_data(0, pieces)
    assert_equal HTTP3::ErrorCode::INTERNAL_ERROR, closed_with(server)
    server = server()
    server.stream_data(0, headers(POST))
    pieces.bytes.each_slice(1000) do |slice|
      server.stream_data(0, slice.pack("C*"))
      events(server)
    end
    assert_nil closed_with(server)
  end

  # The trailers take what the header section left of the limit, as QPACK
  # counts it, and the stream stops with H3_EXCESSIVE_LOAD past it; a
  # HEADERS frame past four times the limit stops it unread.
  def test_trailers_past_the_limit
    size = POST.sum { |name, value| name.bytesize + value.bytesize + 32 }
    left = 300 - size
    [
      [headers([["x-fill", "x" * (left - 32 - 6)]]), false],
      [headers([["x-fill", "x" * (left - 32 - 6 + 1)]]), true],
      [Frame.encode(Frame::Headers.new(field_section: "\x00" * 1201)), true]
    ].each do |trailers, stops|
      server = server(max_field_section_size: 300)
      server.stream_data(0, headers(POST) + trailers)
      seen = events(server)
      if stops
        assert_stopped server, HTTP3::ErrorCode::EXCESSIVE_LOAD, seen
      else
        assert_kind_of HTTP3::Event::Trailers, seen.last
      end
    end
  end
end
