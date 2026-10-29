require "raiha/next/test_helper"
require "raiha/next/support/http3_pair"
require "raiha/next/quic"
require "stringio"
require "json"

# The qlog of an HTTP/3 connection (draft-ietf-quic-qlog-h3-events-12):
# its events, what the peer sent cut short in them, and the same trace as
# the QUIC connection under it.
class RaihaNextHTTP3QlogTest < Minitest::Test
  include NextHTTP3Pair

  Frame = HTTP3::Frame
  QPACK = HTTP3::QPACK
  GET = [[":method", "GET"], [":scheme", "https"], [":authority", "example.com"], [":path", "/"]].freeze

  # Keeps the records a tracer writes.
  class Records
    attr_reader :all

    def initialize = @all = []

    def record(name, data) = @all << [name, JSON.parse(JSON.generate(data))]
  end

  def headers(fields, stream_id: 0) = Frame.encode(Frame::Headers.new(field_section: QPACK::Encoder.new.encode(stream_id, fields.map { QPACK::Field.new(name: _1, value: _2) })))

  def server(records)
    server = HTTP3::Connection.server(tracer: HTTP3::Qlog::Tracer.new(records))
    server.start(**SERVER_STREAMS)
    server
  end

  def test_the_events_of_a_request
    records = Records.new
    server = server(records)
    server.stream_data(2, "\x00".b + Frame.encode(HTTP3::Settings.new.to_frame))
    server.stream_data(0, headers(GET + [["priority", "u=1"]]) + Frame.encode(Frame::Data.new(data: "abc")) + "\x21\x00".b)
    server.send_headers(0, [[":status", "200"]])
    server.send_data(0, "ok", fin: true)
    names = records.all.map(&:first)
    assert_equal %w[http3:parameters_set http3:stream_type_set http3:stream_type_set http3:stream_type_set http3:frame_created], names.first(5)
    assert_equal({ "initiator" => "local", "max_field_section_size" => 65_536, "max_table_capacity" => 0, "blocked_streams_count" => 0,
                   "extended_connect" => 1, "h3_datagram" => 0 }, records.all.first.last)
    assert_includes records.all, ["http3:stream_type_set", { "initiator" => "remote", "stream_id" => 2, "stream_type" => "control" }]
    assert_includes records.all, ["http3:parameters_set", { "initiator" => "remote", "max_field_section_size" => 65_536, "max_table_capacity" => 0,
                                                              "blocked_streams_count" => 0, "extended_connect" => 0, "h3_datagram" => 0 }]
    assert_includes records.all, ["http3:stream_type_set", { "initiator" => "remote", "stream_id" => 0, "stream_type" => "request" }]
    parsed = records.all.filter_map { |name, data| data["frame"] if name == "http3:frame_parsed" && data["stream_id"] == 0 }
    assert_equal [
      { "frame_type" => "headers", "headers" => (GET + [["priority", "u=1"]]).map { |name, value| { "name" => name, "value" => value } } },
      { "frame_type" => "data", "raw" => { "payload_length" => 3 } }, { "frame_type" => "reserved", "frame_type_bytes" => 0x21, "raw" => { "payload_length" => 0 } }
    ], parsed
    assert_includes records.all, ["http3:priority_updated", { "stream_id" => 0, "new" => "u=1" }]
    created = records.all.filter_map { |name, data| data["frame"]["frame_type"] if name == "http3:frame_created" && data["stream_id"] == 0 }
    assert_equal %w[headers data], created
  end

  # What the peer sent is cut short: a name or value to MAX_FIELD_BYTES,
  # with its whole length; a field section to MAX_FIELDS lines, the rest
  # counted; and what is not text goes as hex.
  def test_what_the_peer_sent_is_cut_short
    records = Records.new
    server = HTTP3::Connection.server(settings: HTTP3::Settings.new(max_field_section_size: 100_000), tracer: HTTP3::Qlog::Tracer.new(records))
    fields = GET + [["x-long", "x" * 1000], ["x-bytes", "\x01\xff".b]] + Array.new(70) { ["x-#{_1}", "v"] }
    server.stream_data(0, headers(fields))
    frame = records.all.find { |name, _| name == "http3:frame_parsed" }.last["frame"]
    assert_equal HTTP3::Qlog::Tracer::MAX_FIELDS, frame["headers"].size
    assert_equal fields.size - HTTP3::Qlog::Tracer::MAX_FIELDS, frame["raiha:headers_omitted"]
    assert_equal({ "name" => "x-long", "value" => "x" * 256, "raiha:value_length" => 1000 }, frame["headers"][4])
    assert_equal({ "name" => "x-bytes", "value_bytes" => "01ff" }, frame["headers"][5])
  end

  # A Priority Field Value that is not text goes as hex, so that the trace
  # stays JSON whatever the peer sends.
  # A value of a field that carries credentials goes as its length alone.
  def test_credentials_are_left_out
    records = Records.new
    server = server(records)
    server.stream_data(2, "\x00".b + Frame.encode(HTTP3::Settings.new.to_frame))
    server.stream_data(0, headers(GET + [["authorization", "Bearer secret"], ["cookie", "session=1"], ["accept", "*/*"]]))
    server.send_headers(0, [[":status", "200"], ["set-cookie", "session=2"]], fin: true)
    fields = records.all.select { |name, _| name.start_with?("http3:frame_") }.flat_map { |_, data| data.dig("frame", "headers") || [] }
    assert_equal [{ "name" => "authorization", "raiha:value_length" => 13 }, { "name" => "cookie", "raiha:value_length" => 9 },
      { "name" => "accept", "value" => "*/*" }, { "name" => "set-cookie", "raiha:value_length" => 9 }],
      fields.reject { |field| field["name"].start_with?(":") }
    refute_match(/secret|session/, JSON.generate(records.all))
  end

  def test_a_priority_update_that_is_not_text
    io = StringIO.new
    quic = Raiha::Next::QUIC::Qlog::Tracer.new(io, vantage_point: :server, event_schemas: [HTTP3::Qlog::EVENT_SCHEMA])
    server = server(quic)
    server.stream_data(2, "\x00".b + Frame.encode(HTTP3::Settings.new.to_frame) + Frame.encode(Frame::PriorityUpdate.new(element_id: 0, priority: "u=\xff\xfe".b)))
    frame = io.string.split("\x1e").drop(1).map { JSON.parse(_1) }.last.dig("data", "frame")
    assert_equal({ "frame_type" => "priority_update", "stream_id" => 0, "priority_field_value_bytes" => "753dfffe" }, frame)
    refute server.closed?
  end

  def test_settings_and_frames_not_known
    records = Records.new
    server = server(records)
    server.stream_data(2, "\x00".b + Frame.encode(Frame::Settings.new(settings: [[0x06, 100], [0x21, 1], [0x99, 2]])) + "\x12\x00".b)
    settings = records.all.find { |name, data| name == "http3:frame_parsed" && data["frame"]["frame_type"] == "settings" }.last["frame"]["settings"]
    assert_equal [
      { "name" => "settings_max_field_section_size", "value" => 100 }, { "name" => "reserved", "name_bytes" => 0x21, "value" => 1 },
      { "name" => "unknown", "name_bytes" => 0x99, "value" => 2 }
    ], settings
    assert_includes records.all, ["http3:frame_parsed", { "stream_id" => 2, "frame" => { "frame_type" => "unknown", "frame_type_bytes" => 0x12, "raw" => { "payload_length" => 0 } } }]
  end

  # The events go into the QUIC connection's trace, under its limits.
  def test_into_the_trace_of_quic
    io = StringIO.new
    quic = Raiha::Next::QUIC::Qlog::Tracer.new(io, vantage_point: :server, event_schemas: [HTTP3::Qlog::EVENT_SCHEMA], max_bytes: 2000)
    server = server(quic)
    20.times { |index| server.stream_data(index * 4, headers(GET, stream_id: index * 4)) }
    records = io.string.split("\x1e").drop(1).map { JSON.parse(_1) }
    assert_equal ["urn:ietf:params:qlog:events:quic", "urn:ietf:params:qlog:events:http3-12"], records.first.dig("trace", "event_schemas")
    assert_equal "http3:parameters_set", records[1]["name"]
    assert_equal "raiha:qlog_stopped", records.last["name"]
    assert_operator io.string.bytesize, :<=, 2000
  end
end
