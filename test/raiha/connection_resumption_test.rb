require "test_helper"
require "raiha/connection"
require "raiha/tls/session_ticket_store"
require "support/test_certificate"

# QUIC-layer end-to-end resumption: a server emits a NewSessionTicket
# in 1-RTT (RFC 9001 §4.6.1), the client stores it, and a fresh
# Connection wired to the same SessionTicketStore PSK-resumes via the
# TLS layer (RFC 8446 §2.2).
class RaihaConnectionResumptionTest < Minitest::Test
  include TestCertificate

  def test_quic_connection_resumes_with_shared_session_ticket_store
    shared_store = Raiha::TLS::SessionTicketStore.new

    # First connection: full handshake plus NST delivery.
    first_client, first_server = drive_full_handshake(client_store: nil, server_store: shared_store)
    assert first_client.handshake_complete?
    assert first_server.handshake_complete?

    # Server queued a NewSessionTicket in complete_handshake; deliver it.
    server_packets = first_server.get_packets_to_send
    server_packets.each { |p| first_client.handle_packet(p) }

    client_store = first_client.tls_session_ticket_store
    refute_nil client_store, "client should expose its ticket store"
    refute_empty client_store.instance_variable_get(:@tickets),
      "client should have stored at least one ticket"

    # Second connection sharing the same stores → resumes via PSK.
    second_client, second_server = drive_full_handshake(
      client_store: client_store,
      server_store: shared_store
    )
    assert second_client.handshake_complete?
    assert second_server.handshake_complete?

    server_tls = second_server.instance_variable_get(:@tls_adapter).tls
    client_tls = second_client.instance_variable_get(:@tls_adapter).tls
    assert server_tls.psk_mode?, "second server should PSK-resume"
    refute client_tls.peer_authenticated?,
      "second client should skip Certificate path on resumption"
  end

  private def drive_full_handshake(client_store:, server_store:)
    dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate

    client = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: dest_connection_id,
      session_ticket_store: client_store
    )
    server = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: dest_connection_id,
      dest_connection_id: dest_connection_id,
      tls_config: create_server_config,
      session_ticket_store: server_store
    )

    client.start_handshake
    client.get_packets_to_send.each { |p| server.handle_packet(p) }
    server.get_packets_to_send.each { |p| client.handle_packet(p) }
    client.get_packets_to_send.each { |p| server.handle_packet(p) }

    [client, server]
  end
end
