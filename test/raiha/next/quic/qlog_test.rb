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

  # A key update is told for the keys of both directions, with no key.
  def test_a_key_update
    io = StringIO.new
    QUIC::Qlog::Tracer.new(io, vantage_point: :server).key_updated(level: :one_rtt, now: 1.5)
    updates = records(io).drop(1)
    assert_equal [[1500.0, "client_1rtt_secret"], [1500.0, "server_1rtt_secret"]], updates.map { [_1["time"], _1.dig("data", "key_type")] }
    assert updates.none? { _1["data"].key?("old") || _1["data"].key?("new") }
  end
end
