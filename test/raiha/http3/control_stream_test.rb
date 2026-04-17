require "test_helper"
require "raiha/http3"
require "raiha/connection"
require "support/test_certificate"

class RaihaHTTP3ControlStreamTest < Minitest::Test
  include TestCertificate

  def test_parse_incoming_control_stream
    settings = Raiha::HTTP3::SettingsFrame.new
    settings.settings[Raiha::HTTP3::SettingsFrame::SETTINGS[:qpack_max_table_capacity]] = 4096
    settings.settings[Raiha::HTTP3::SettingsFrame::SETTINGS[:qpack_blocked_streams]] = 100

    data = Raiha::Quic::Varint.encode(Raiha::HTTP3::StreamType::CONTROL) + settings.serialize

    stream_type, frames = Raiha::HTTP3::ControlStream.parse_incoming(data)
    assert_equal Raiha::HTTP3::StreamType::CONTROL, stream_type
    assert_equal 1, frames.size
    assert_instance_of Raiha::HTTP3::SettingsFrame, frames.first
    assert_equal 4096, frames.first.qpack_max_table_capacity
  end

  def test_parse_non_control_stream_returns_only_stream_type
    data = Raiha::Quic::Varint.encode(Raiha::HTTP3::StreamType::QPACK_ENCODER) + "raw-payload".b
    stream_type, frames = Raiha::HTTP3::ControlStream.parse_incoming(data)
    assert_equal Raiha::HTTP3::StreamType::QPACK_ENCODER, stream_type
    assert_empty frames
  end

  def test_extract_settings_returns_nil_when_missing
    assert_nil Raiha::HTTP3::ControlStream.extract_settings([])
    assert_nil Raiha::HTTP3::ControlStream.extract_settings([Raiha::HTTP3::GoawayFrame.new(0)])
  end

  def test_client_setup_control_stream_and_server_reads_settings
    client_conn, server_conn = complete_handshake

    http3_client = Raiha::HTTP3::Client.new(connection: client_conn)
    http3_server = Raiha::HTTP3::Server.new(connection: server_conn)

    client_control = http3_client.setup_control_stream(
      settings: { Raiha::HTTP3::SettingsFrame::SETTINGS[:qpack_max_table_capacity] => 128 }
    )
    refute_predicate client_control.stream_id, :bidirectional?

    client_conn.get_packets_to_send.each { |p| server_conn.handle_packet(p) }

    server_side_stream = server_conn.streams.get_stream(client_control.stream_id.value)
    refute_nil server_side_stream

    peer_settings = http3_server.receive_peer_control_stream(server_side_stream)
    refute_nil peer_settings
    assert_equal 128, peer_settings.qpack_max_table_capacity
  end

  def test_server_setup_control_stream_and_client_reads_settings
    client_conn, server_conn = complete_handshake

    http3_client = Raiha::HTTP3::Client.new(connection: client_conn)
    http3_server = Raiha::HTTP3::Server.new(connection: server_conn)

    server_control = http3_server.setup_control_stream(
      settings: { Raiha::HTTP3::SettingsFrame::SETTINGS[:max_field_section_size] => 65536 }
    )

    server_conn.get_packets_to_send.each { |p| client_conn.handle_packet(p) }

    client_side_stream = client_conn.streams.get_stream(server_control.stream_id.value)
    refute_nil client_side_stream

    peer_settings = http3_client.receive_peer_control_stream(client_side_stream)
    refute_nil peer_settings
    assert_equal 65536, peer_settings.max_field_section_size
  end

  private def complete_handshake
    dest_cid = Raiha::Quic::Protocol::ConnectionID.generate
    client_conn = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: dest_cid
    )
    server_conn = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: dest_cid,
      dest_connection_id: dest_cid,
      tls_config: create_server_config
    )

    client_conn.start_handshake
    client_conn.get_packets_to_send.each { |p| server_conn.handle_packet(p) }
    server_conn.get_packets_to_send.each { |p| client_conn.handle_packet(p) }
    client_conn.get_packets_to_send.each { |p| server_conn.handle_packet(p) }

    [client_conn, server_conn]
  end
end
