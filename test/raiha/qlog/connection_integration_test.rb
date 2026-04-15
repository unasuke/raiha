require "test_helper"
require "raiha/connection"
require "support/test_certificate"
require "stringio"

class RaihaQlogConnectionIntegrationTest < Minitest::Test
  include TestCertificate

  def test_qlog_records_handshake_events
    output = StringIO.new

    dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate
    client = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: dest_connection_id
    )
    server = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: dest_connection_id,
      dest_connection_id: dest_connection_id,
      tls_config: create_server_config
    )

    client.enable_qlog(output: output, title: "Handshake Test")

    client.start_handshake
    client.get_packets_to_send.each { |p| server.handle_packet(p) }
    server.get_packets_to_send.each { |p| client.handle_packet(p) }
    client.get_packets_to_send.each { |p| server.handle_packet(p) }

    assert client.handshake_complete?

    client.flush_qlog

    json = JSON.parse(output.string)
    assert_equal "0.4", json["qlog_version"]
    assert_equal "Handshake Test", json["title"]

    trace = json["traces"][0]
    assert_equal "client", trace["vantage_point"]["type"]

    events = trace["events"]
    refute_empty events

    event_names = events.map { |e| e["name"] }
    assert_includes event_names, "connectivity:connection_started"
    assert_includes event_names, "transport:packet_sent"
    assert_includes event_names, "transport:packet_received"
    assert_includes event_names, "connectivity:connection_state_updated"
  end

  def test_qlog_not_enabled_does_not_error
    dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate
    client = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: dest_connection_id
    )
    server = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: dest_connection_id,
      dest_connection_id: dest_connection_id,
      tls_config: create_server_config
    )

    client.start_handshake
    client.get_packets_to_send.each { |p| server.handle_packet(p) }
    server.get_packets_to_send.each { |p| client.handle_packet(p) }
    client.get_packets_to_send.each { |p| server.handle_packet(p) }

    assert client.handshake_complete?
    assert_nil client.qlog_writer
  end

  def test_qlog_packet_sent_includes_frames
    output = StringIO.new

    dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate
    client = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: dest_connection_id
    )

    client.enable_qlog(output: output)
    client.start_handshake
    client.get_packets_to_send
    client.flush_qlog

    json = JSON.parse(output.string)
    sent_events = json["traces"][0]["events"].select { |e| e["name"] == "transport:packet_sent" }
    refute_empty sent_events

    first_sent = sent_events.first
    assert_equal "initial", first_sent["data"]["header"]["packet_type"]
    assert_kind_of Array, first_sent["data"]["frames"]
    refute_empty first_sent["data"]["frames"]

    crypto_frame = first_sent["data"]["frames"].find { |f| f["frame_type"] == "crypto" }
    refute_nil crypto_frame, "Initial packet should contain a CRYPTO frame"
    assert_equal 0, crypto_frame["offset"]
  end

  def test_qlog_state_transition_on_handshake_complete
    output = StringIO.new

    dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate
    client = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: dest_connection_id
    )
    server = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: dest_connection_id,
      dest_connection_id: dest_connection_id,
      tls_config: create_server_config
    )

    client.enable_qlog(output: output)
    client.start_handshake
    client.get_packets_to_send.each { |p| server.handle_packet(p) }
    server.get_packets_to_send.each { |p| client.handle_packet(p) }
    client.get_packets_to_send.each { |p| server.handle_packet(p) }

    client.flush_qlog

    json = JSON.parse(output.string)
    state_events = json["traces"][0]["events"].select { |e| e["name"] == "connectivity:connection_state_updated" }
    refute_empty state_events

    completed = state_events.find { |e| e["data"]["new"] == "connected" }
    refute_nil completed, "Should have a state transition to connected"
    assert_equal "handshaking", completed["data"]["old"]
  end
end
