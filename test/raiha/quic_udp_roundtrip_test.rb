require "test_helper"
require "raiha/connection"
require "support/test_certificate"
require "socket"
require "timeout"

class RaihaQuicUDPRoundtripTest < Minitest::Test
  include TestCertificate

  def test_initial_packet_meets_minimum_size
    client_connection = create_client_connection
    client_connection.start_handshake

    packets = client_connection.get_packets_to_send
    refute_empty packets

    assert packets.first.bytesize >= 1200,
      "Initial packet should be at least 1200 bytes, got #{packets.first.bytesize}"
  end

  def test_udp_initial_packet_exchange
    client_port = find_available_port
    server_port = find_available_port

    client_socket = UDPSocket.new
    client_socket.bind("127.0.0.1", client_port)

    server_socket = UDPSocket.new
    server_socket.bind("127.0.0.1", server_port)

    # Use the same DCID so both sides derive the same Initial keys
    dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate
    src_connection_id = Raiha::Quic::Protocol::ConnectionID.generate

    client_connection = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: src_connection_id,
      dest_connection_id: dest_connection_id
    )

    server_connection = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: dest_connection_id,
      dest_connection_id: dest_connection_id,
      tls_config: create_server_config
    )

    Timeout.timeout(5) do
      # Client starts handshake and sends Initial packet
      client_connection.start_handshake
      client_packets = client_connection.get_packets_to_send

      client_packets.each do |packet|
        client_socket.send(packet, 0, "127.0.0.1", server_port)
      end

      # Server receives Initial packet
      data, = server_socket.recvfrom(65535)
      server_connection.handle_packet(data)

      # Verify server processed the ClientHello
      server_crypto = server_connection.instance_variable_get(:@crypto_setup)
      assert server_crypto.available?(:handshake),
        "Server should derive handshake keys after receiving Initial packet over UDP"
    end
  ensure
    client_socket&.close
    server_socket&.close
  end

  private def create_client_connection
    Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.generate
    )
  end

  private def find_available_port
    server = UDPSocket.new
    server.bind("127.0.0.1", 0)
    port = server.addr[1]
    server.close
    port
  end
end
