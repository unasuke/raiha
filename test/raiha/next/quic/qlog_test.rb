require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"
require "stringio"
require "json"

# The qlog a connection writes: a JSON Text Sequence that qlog readers and
# qvis take.
class RaihaNextQUICQlogTest < Minitest::Test
  include NextQUICPair

  # The records of `io`, each after a Record Separator and before a line
  # feed, as JSON.
  def records(io)
    text = io.string
    assert text.start_with?("\x1e")
    text.split("\x1e").drop(1).map do |record|
      assert record.end_with?("\n"), record
      JSON.parse(record)
    end
  end

  def qlog_of_a_handshake
    client_io = StringIO.new
    server_io = StringIO.new
    client = client_connection(tracer: QUIC::Qlog::Tracer.new(client_io, vantage_point: :client))
    server = server_connection(tracer: QUIC::Qlog::Tracer.new(server_io, vantage_point: :server, title: "server"))
    handshake(client, server)
    assert client.handshake_complete?
    [records(client_io), records(server_io)]
  end

  # The header has what the qlog draft asks, and the qlog_version and
  # qlog_format qvis looks for.
  def test_the_header
    client, server = qlog_of_a_handshake
    header = client.first
    assert_equal "urn:ietf:params:qlog:file:sequential", header["file_schema"]
    assert_equal "application/qlog+json-seq", header["serialization_format"]
    assert_equal ["0.3", "JSON-SEQ"], [header["qlog_version"], header["qlog_format"]]
    assert_equal "client", header.dig("trace", "vantage_point", "type")
    assert_equal ["urn:ietf:params:qlog:events:quic"], header.dig("trace", "event_schemas")
    assert_equal ["server", "server"], [server.first["title"], server.first.dig("trace", "vantage_point", "type")]
  end

  def test_the_events_of_a_handshake
    client, = qlog_of_a_handshake
    events = client.drop(1)
    assert events.all? { _1["time"].is_a?(Numeric) && _1["name"].is_a?(String) && _1["data"].is_a?(Hash) }
    first = events.find { _1["name"] == "quic:packet_sent" }
    assert_equal "initial", first.dig("data", "header", "packet_type")
    assert_equal 1200, first.dig("data", "raw", "length")
    crypto = first.dig("data", "frames").find { _1["frame_type"] == "crypto" }
    assert_equal 0, crypto["offset"]
    assert_operator crypto.dig("raw", "length"), :>, 0
    assert_equal %w[local remote], events.select { _1["name"] == "quic:parameters_set" }.map { _1.dig("data", "owner") }
    names = events.map { _1["name"] }.uniq
    assert_includes names, "quic:packet_received"
    assert_includes names, "quic:recovery_metrics_updated"
    refute names.any? { _1.include?("raiha2") }
  end

  # TLS's traces go into the same trace, under "raiha:tls_".
  def test_tls_traces
    client, = qlog_of_a_handshake
    assert client.any? { _1["name"] == "raiha:tls_transcript_updated" }
  end

  # The frames of paths and connection IDs go with what they carry: the
  # sequence numbers, the IDs and token, and the data of a challenge and
  # its response, in hex.
  def test_frames_of_paths_and_connection_ids
    io = StringIO.new
    frames = [
      QUIC::Wire::Frame::NewConnectionID.new(sequence_number: 1, retire_prior_to: 0, connection_id: "\x01".b * 8,
        stateless_reset_token: "\x02".b * 16),
      QUIC::Wire::Frame::RetireConnectionID.new(sequence_number: 2),
      QUIC::Wire::Frame::PathChallenge.new(data: "abcdefgh".b), QUIC::Wire::Frame::PathResponse.new(data: "abcdefgh".b)
    ]
    header = QUIC::Tracer::PacketHeader.new(packet_type: :one_rtt, packet_number: 5, version: nil, dcid: "\x03".b * 8, scid: nil, key_phase: 0)
    QUIC::Qlog::Tracer.new(io, vantage_point: :server).packet_sent(header:, frames:, raw_length: 100, now: 1.0)
    assert_equal [
      { "frame_type" => "new_connection_id", "sequence_number" => 1, "retire_prior_to" => 0, "connection_id" => "01" * 8,
        "stateless_reset_token" => "02" * 16 },
      { "frame_type" => "retire_connection_id", "sequence_number" => 2 },
      { "frame_type" => "path_challenge", "data" => "6162636465666768" }, { "frame_type" => "path_response", "data" => "6162636465666768" }
    ], records(io).last.dig("data", "frames")
  end

  # A key update is told for the keys of both directions, with no key.
  def test_a_key_update
    io = StringIO.new
    QUIC::Qlog::Tracer.new(io, vantage_point: :server).key_updated(level: :one_rtt, now: 1.5)
    updates = records(io).drop(1)
    assert_equal [[1500.0, "client_1rtt_secret"], [1500.0, "server_1rtt_secret"]], updates.map { [_1["time"], _1.dig("data", "key_type")] }
    assert updates.none? { _1["data"].key?("old") || _1["data"].key?("new") }
  end

  # A trace writes no more than max_bytes: it ends with a record saying it
  # stopped, and the connection lists no more frames for it.
  def test_a_trace_stops_at_max_bytes
    io = StringIO.new
    tracer = QUIC::Qlog::Tracer.new(io, vantage_point: :client, max_bytes: 4096)
    client = client_connection(tracer:)
    handshake(client, server_connection)
    assert client.handshake_complete?
    assert_operator io.string.bytesize, :<=, 4096
    trace = records(io)
    assert_equal "urn:ietf:params:qlog:file:sequential", trace.first["file_schema"]
    assert_equal ["raiha:qlog_stopped", { "reason" => "max_bytes", "max_bytes" => 4096 }], [trace.last["name"], trace.last["data"]]
    assert_equal 1, trace.count { _1["name"] == "raiha:qlog_stopped" }
    refute tracer.trace_frames?
    written = io.string.bytesize
    tracer.key_updated(level: :one_rtt, now: 1.0)
    assert_equal written, io.string.bytesize
  end

  # The traces given one budget write no more than it together; one begun
  # once it is spent writes nothing.
  def test_traces_share_a_budget
    budget = QUIC::Qlog::Budget.new(max_bytes: 6000)
    ios = Array.new(2) { StringIO.new }
    clients = ios.map { |io| client_connection(tracer: QUIC::Qlog::Tracer.new(io, vantage_point: :client, budget:)) }
    clients.each { |client| handshake(client, server_connection) }
    assert_equal ios.sum { _1.string.bytesize }, budget.spent
    assert_operator budget.spent, :<=, 6000
    stopped = records(ios.last).last
    assert_equal ["raiha:qlog_stopped", { "reason" => "budget", "max_bytes" => 6000 }], [stopped["name"], stopped["data"]]
    late = StringIO.new
    refute QUIC::Qlog::Tracer.new(late, vantage_point: :client, budget:).trace_frames?
    assert_empty late.string
    assert_raises(ArgumentError) { QUIC::Qlog::Budget.new(max_bytes: 0) }
  end

  # A layer above QUIC writes its events into the same trace, at the time
  # of the event before them, and names its schema.
  def test_events_of_a_layer_above
    io = StringIO.new
    tracer = QUIC::Qlog::Tracer.new(io, vantage_point: :server, event_schemas: ["urn:ietf:params:qlog:events:http3-12"])
    tracer.key_updated(level: :one_rtt, now: 2.0)
    tracer.record("http3:frame_parsed", { stream_id: 0, frame: { frame_type: "data" } })
    trace = records(io)
    assert_equal ["urn:ietf:params:qlog:events:quic", "urn:ietf:params:qlog:events:http3-12"], trace.first.dig("trace", "event_schemas")
    assert_equal [2000.0, "http3:frame_parsed", { "stream_id" => 0, "frame" => { "frame_type" => "data" } }], trace.last.values_at("time", "name", "data")
  end

  def test_max_bytes_by_default
    tracer = QUIC::Qlog::Tracer.new(StringIO.new, vantage_point: :client)
    assert_equal 64 * 1024 * 1024, QUIC::Qlog::Tracer::DEFAULT_MAX_BYTES
    assert tracer.trace_frames?
    assert_raises(ArgumentError) { QUIC::Qlog::Tracer.new(StringIO.new, vantage_point: :client, max_bytes: 0) }
    assert_raises(ArgumentError) { QUIC::Qlog::Tracer.new(StringIO.new, vantage_point: :client, max_bytes: "1") }
  end
end
