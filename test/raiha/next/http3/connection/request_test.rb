require "raiha/next/test_helper"
require "raiha/next/support/http3_pair"

# A server's request streams (RFC 9114 "HTTP Request Lifecycle"): a field
# section first, decoded by QPACK or waiting on it, none of the frames
# that go elsewhere, and the end of the stream told with the last event.
class RaihaNextHTTP3ConnectionRequestTest < Minitest::Test
  include NextHTTP3Pair

  Frame = HTTP3::Frame
  QPACK = HTTP3::QPACK
  GET = [[":method", "GET"], [":scheme", "https"], [":authority", "example.com"], [":path", "/"]].freeze

  def server(**settings)
    server = HTTP3::Connection.server(settings: HTTP3::Settings.new(**settings))
    server.start(**SERVER_STREAMS)
    sent(server)
    actions(server)
    server
  end

  def events(connection) = [].tap { |all| connection.each_event { all << _1 } }

  def headers_frame(fields, stream_id: 0)
    encoded = QPACK::Encoder.new.encode(stream_id, fields.map { |name, value| QPACK::Field.new(name:, value:) })
    Frame.encode(Frame::Headers.new(field_section: encoded))
  end

  def closed_with(connection) = actions(connection).grep(HTTP3::Action::Close).first&.error_code

  def test_a_request_and_its_end
    server = server()
    server.stream_data(0, headers_frame(GET), fin: true)
    assert_equal [HTTP3::Event::Headers.new(stream_id: 0, headers: GET, fin: true)], events(server)
    assert_empty actions(server)
  end

  # The end comes later: with the field section if it is still to be
  # taken, else alone.
  def test_the_end_comes_later
    server = server()
    server.stream_data(0, headers_frame(GET))
    server.stream_data(0, "".b, fin: true)
    assert_equal [HTTP3::Event::Headers.new(stream_id: 0, headers: GET, fin: true)], events(server)
    server.stream_data(4, headers_frame(GET, stream_id: 4))
    assert_equal [HTTP3::Event::Headers.new(stream_id: 4, headers: GET, fin: false)], events(server)
    server.stream_data(4, "".b, fin: true)
    assert_equal [HTTP3::Event::Data.new(stream_id: 4, data: "", fin: true)], events(server)
  end

  def test_a_byte_at_a_time
    server = server()
    headers_frame(GET).each_char { |byte| server.stream_data(0, byte) }
    assert_equal [HTTP3::Event::Headers.new(stream_id: 0, headers: GET, fin: false)], events(server)
  end

  def test_the_headers_are_shareable
    server = server()
    server.stream_data(0, headers_frame(GET))
    assert Ractor.shareable?(events(server).first)
  end

  # RFC 9114 "HTTP Framing Layer" and "HTTP Message Framing".
  def test_frames_a_request_stream_does_not_carry
    [
      Frame.encode(Frame::Data.new(data: "x")), Frame.encode(Frame::Settings.new(settings: [])), Frame.encode(Frame::GoAway.new(id: 0)),
      Frame.encode(Frame::CancelPush.new(push_id: 0)), Frame.encode(Frame::MaxPushId.new(push_id: 0)),
      Frame.encode(Frame::PriorityUpdate.new(element_id: 0, priority: "")),
      Frame.encode(Frame::PushPromise.new(push_id: 0, field_section: "\x00\x00")), "\x02\x00".b, "\x09\x00".b
    ].each do |frame|
      server = server()
      server.stream_data(0, frame)
      assert_equal HTTP3::ErrorCode::FRAME_UNEXPECTED, closed_with(server), frame.inspect
    end
  end

  def test_frames_not_known_before_the_headers
    server = server()
    server.stream_data(0, "\x21\x02ab".b + headers_frame(GET))
    assert_equal [HTTP3::Event::Headers.new(stream_id: 0, headers: GET, fin: false)], events(server)
  end

  def test_a_stream_ended_before_its_headers
    [["".b, 0], ["\x21\x00".b, 4]].each do |bytes, stream_id|
      server = server()
      server.stream_data(stream_id, bytes, fin: true)
      code = HTTP3::ErrorCode::REQUEST_INCOMPLETE
      assert_equal [HTTP3::Action::StopSending.new(stream_id:, error_code: code), HTTP3::Action::Reset.new(stream_id:, error_code: code)], actions(server)
      assert_empty events(server)
    end
  end

  def test_a_stream_ended_within_a_frame
    server = server()
    server.stream_data(0, headers_frame(GET).byteslice(0, 3), fin: true)
    assert_equal HTTP3::ErrorCode::FRAME_ERROR, closed_with(server)
  end

  # A field section that refers to an entry yet to come waits for it, and
  # what follows it with it; the end of the stream too.
  def test_a_field_section_waits_on_qpack
    server = server(qpack_max_table_capacity: 4096, qpack_blocked_streams: 1)
    # Required Insert Count 1 (as encoded with 128 entries at most), Base
    # 1; the static entries 17 (:method GET), 23 (:scheme https) and 1
    # (:path /), :authority by the name of static entry 0, and the dynamic
    # entry of relative index 0.
    section = Frame.encode(Frame::Headers.new(field_section: "\x02\x00\xd1\xd7\xc1\x50\x01a\x80".b))
    server.stream_data(0, section + "\x21\x00".b, fin: true)
    assert_equal [HTTP3::Event::Blocked.new(stream_id: 0)], events(server)
    insert = QPACK::Writer.new.integer(4096, 5, 0x20).string("x-name", 6, 0x40).string("value", 8).to_s
    server.stream_data(6, "\x02".b + insert)
    headers = [[":method", "GET"], [":scheme", "https"], [":path", "/"], [":authority", "a"], ["x-name", "value"]]
    assert_equal [HTTP3::Event::Headers.new(stream_id: 0, headers:, fin: true)], events(server)
    assert_empty actions(server)
  end

  # While a field section waits, what follows it waits within bounds: DATA
  # no longer than a field section may be, and no more than MAX_WAITING
  # frames; past them the stream stops with H3_EXCESSIVE_LOAD.
  def test_what_waits_on_qpack_is_bounded
    code = HTTP3::ErrorCode::EXCESSIVE_LOAD
    stopped = [HTTP3::Action::StopSending.new(stream_id: 0, error_code: code), HTTP3::Action::Reset.new(stream_id: 0, error_code: code)]
    section = Frame.encode(Frame::Headers.new(field_section: "\x02\x00\x80".b))
    {
      Frame.encode(Frame::Data.new(data: "x" * 400)) => false, Frame.encode(Frame::Data.new(data: "x" * 401)) => true,
      "\x21\x00".b * HTTP3::Connection::MAX_WAITING => false, "\x21\x00".b * (HTTP3::Connection::MAX_WAITING + 1) => true
    }.each do |following, stops|
      server = server(qpack_max_table_capacity: 4096, qpack_blocked_streams: 1, max_field_section_size: 100)
      server.stream_data(0, section + following)
      assert_equal(stops ? stopped : [], actions(server), following.bytesize)
      refute server.closed?
    end
  end

  # A frame a request stream does not carry is refused while the field
  # section waits too, and the field sections that wait count with the
  # DATA.
  def test_what_waits_on_qpack_is_checked_and_counted
    section = Frame.encode(Frame::Headers.new(field_section: "\x02\x00\x80".b))
    server = server(qpack_max_table_capacity: 4096, qpack_blocked_streams: 1, max_field_section_size: 100)
    server.stream_data(0, section + Frame.encode(Frame::GoAway.new(id: 0)))
    assert_equal HTTP3::ErrorCode::FRAME_UNEXPECTED, closed_with(server)
    server = server(qpack_max_table_capacity: 4096, qpack_blocked_streams: 1, max_field_section_size: 100)
    trailers = Frame.encode(Frame::Headers.new(field_section: "\x00" * 150))
    server.stream_data(0, section + trailers + trailers)
    assert_empty actions(server)
    server.stream_data(0, trailers)
    assert_equal [HTTP3::Action::StopSending, HTTP3::Action::Reset], actions(server).map(&:class)
  end

  # The bytes of a request stream that ended, or was stopped, which a
  # transport might still hand over, start no request.
  def test_late_bytes_of_a_stream_that_ended
    server = server()
    server.stream_data(0, headers_frame(GET), fin: true)
    server.stream_data(4, headers_frame(GET + [["connection", "close"]], stream_id: 4))
    events(server)
    actions(server)
    [0, 4].each { |stream_id| server.stream_data(stream_id, headers_frame(GET, stream_id:)) }
    assert_empty events(server)
    assert_empty actions(server)
  end

  # The IDs of the peer's streams come in order, but their bytes need not:
  # one skipped is taken when it comes, unless it was reset first.
  def test_streams_whose_bytes_come_out_of_order
    server = server()
    [8, 0].each { |stream_id| server.stream_data(stream_id, headers_frame(GET, stream_id:)) }
    server.stream_reset(4, error_code: 0)
    server.stream_data(4, headers_frame(GET, stream_id: 4))
    assert_equal [8, 0], events(server).map(&:stream_id)
    server.stream_data(12, headers_frame(GET, stream_id: 12))
    assert_equal [12], events(server).map(&:stream_id)
  end

  # A request reset while its field section waits is let go by QPACK too.
  def test_a_request_reset_while_waiting
    server = server(qpack_max_table_capacity: 4096, qpack_blocked_streams: 1)
    server.stream_data(0, Frame.encode(Frame::Headers.new(field_section: "\x02\x00\x80".b)))
    events(server)
    server.stream_reset(0, error_code: 0)
    insert = QPACK::Writer.new.integer(4096, 5, 0x20).string("x-name", 6, 0x40).string("value", 8).to_s
    server.stream_data(6, "\x02".b + insert)
    assert_empty events(server)
    assert_equal({ 11 => ["\x40\x01".b, false] }, sent(server))
  end

  # An integer past 62 bits in a field section stops that stream only (RFC
  # 9204 "Implementation Limits").
  def test_a_field_section_qpack_fails_on_stops_the_stream
    server = server()
    server.stream_data(0, Frame.encode(Frame::Headers.new(field_section: "\xff".b * 12)))
    code = QPACK::ErrorCode::DECOMPRESSION_FAILED
    assert_equal [HTTP3::Action::StopSending.new(stream_id: 0, error_code: code), HTTP3::Action::Reset.new(stream_id: 0, error_code: code)], actions(server)
    refute server.closed?
  end

  # RFC 9114 "Malformed Requests and Responses": a stream error of type
  # H3_MESSAGE_ERROR, and the application never sees the request.
  def test_a_malformed_request
    server = server()
    server.stream_data(0, headers_frame(GET + [["connection", "close"]]))
    code = HTTP3::ErrorCode::MESSAGE_ERROR
    assert_equal [HTTP3::Action::StopSending.new(stream_id: 0, error_code: code), HTTP3::Action::Reset.new(stream_id: 0, error_code: code)], actions(server)
    assert_empty events(server)
    refute server.closed?
  end

  # A client takes no stream going both ways that a server opens (RFC
  # 9114 "Bidirectional Streams").
  def test_a_client_takes_no_stream_a_server_opens_both_ways
    client = HTTP3::Connection.client
    client.stream_data(1, headers_frame(GET, stream_id: 1))
    assert_equal HTTP3::ErrorCode::STREAM_CREATION_ERROR, closed_with(client)
  end
end
