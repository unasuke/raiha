require "raiha/next/test_helper"
require "raiha/next/support/http3_pair"

# A server's responses: interim responses, the response, its content as
# the stream takes it, and its trailers.
class RaihaNextHTTP3ConnectionResponseTest < Minitest::Test
  include NextHTTP3Pair

  Frame = HTTP3::Frame
  QPACK = HTTP3::QPACK
  GET = [[":method", "GET"], [":scheme", "https"], [":authority", "example.com"], [":path", "/"]].freeze
  OK = [[":status", "200"], ["content-type", "text/plain"]].freeze

  # A server that has the request on stream 0.
  def server(**options)
    server = HTTP3::Connection.server(**options)
    server.start(**SERVER_STREAMS)
    sent(server)
    actions(server)
    fields = GET.map { |name, value| QPACK::Field.new(name:, value:) }
    server.stream_data(0, Frame.encode(Frame::Headers.new(field_section: QPACK::Encoder.new.encode(0, fields))))
    events(server)
    server
  end

  def events(connection) = [].tap { |all| connection.each_event { all << _1 } }

  # The frames of `bytes`, field sections decoded, and DATA joined.
  def frames(bytes)
    reader = HTTP3::FrameReader.new(max_payload: 100_000)
    decoder = QPACK::Decoder.new
    [].tap do |all|
      reader.feed(bytes) do |item|
        case item
        when Frame::Headers then all << decoder.decode(0, item.field_section).fields.map { [_1.name, _1.value] }
        when Frame::Data then all.last.is_a?(String) ? all.last << item.data : all << (+"" << item.data)
        end
      end
    end
  end

  def test_a_response
    server = server()
    server.send_headers(0, OK)
    assert_equal 5, server.send_data(0, "hello", fin: true)
    bytes, fin = sent(server).fetch(0)
    assert_equal [OK, "hello"], frames(bytes)
    assert fin
  end

  def test_interim_responses_and_trailers
    server = server()
    server.send_headers(0, [[":status", "103"], ["link", "</style.css>; rel=preload"]])
    server.send_headers(0, OK)
    server.send_data(0, "abc")
    server.send_headers(0, [["x-checksum", "1"]])
    bytes, fin = sent(server).fetch(0)
    assert_equal [[[":status", "103"], ["link", "</style.css>; rel=preload"]], OK, "abc", [["x-checksum", "1"]]], frames(bytes)
    assert fin
  end

  def test_a_response_with_no_content
    server = server()
    server.send_headers(0, [[":status", "204"]], fin: true)
    bytes, fin = sent(server).fetch(0)
    assert_equal [[[":status", "204"]]], frames(bytes)
    assert fin
  end

  # The content a stream holds is bounded: what it does not take, the
  # application writes again when Event::Writable says it may.
  def test_content_waits_for_room
    server = server(max_send_buffer: 1000)
    server.send_headers(0, OK)
    sent(server)
    assert_equal 1000, server.send_data(0, "x" * 1500, fin: true)
    assert_equal 0, server.send_data(0, "x" * 500, fin: true)
    assert_empty events(server)
    bytes, fin = sent(server).fetch(0)
    refute fin
    assert_equal [HTTP3::Event::Writable.new(stream_id: 0)], events(server)
    assert_equal 500, server.send_data(0, "x" * 500, fin: true)
    rest, fin = sent(server).fetch(0)
    assert fin
    assert_equal ["x" * 1500], frames(bytes + rest)
    assert_empty events(server)
  end

  def test_misuse
    server = server()
    assert_raises(HTTP3::Error::Usage) { server.send_data(0, "early") }
    assert_raises(HTTP3::Error::Usage) { server.send_headers(4, OK) }
    assert_raises(ArgumentError) { server.send_headers(0, [[":status", "200"], ["Content-Type", "text/plain"]]) }
    assert_raises(ArgumentError) { server.send_headers(0, [["content-type", "text/plain"]]) }
    assert_raises(ArgumentError) { server.send_headers(0, [[":status", "100"]], fin: true) }
    server.send_headers(0, OK)
    assert_raises(ArgumentError) { server.send_headers(0, [[":status", "200"]]) }
    server.send_data(0, "done", fin: true)
    assert_raises(HTTP3::Error::Usage) { server.send_data(0, "more") }
    assert_raises(HTTP3::Error::Usage) { server.send_headers(0, [["x-late", "1"]]) }
  end
end
