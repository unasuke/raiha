require "test_helper"
require "raiha/connection"
require "support/test_certificate"

class RaihaQuicHandshakeRoundtripTest < Minitest::Test
  include TestCertificate

  def test_client_produces_initial_crypto_data
    client_connection = create_client_connection
    client_connection.start_handshake

    packets = client_connection.get_packets_to_send
    refute_empty packets, "Client should produce Initial packet with ClientHello"
  end

  def test_client_server_crypto_data_exchange
    client_connection = create_client_connection
    server_connection = create_server_connection

    # Client starts handshake and produces ClientHello crypto data
    client_connection.start_handshake
    client_crypto = client_connection.instance_variable_get(:@crypto_setup)
    client_initial_data = client_crypto.get_crypto_data(level: :initial)

    refute_nil client_initial_data
    assert client_initial_data.bytesize > 0

    # Feed ClientHello to server's TLS adapter directly
    server_tls_adapter = server_connection.instance_variable_get(:@tls_adapter)
    server_tls_adapter.receive_crypto_data(client_initial_data, level: :initial)

    # Server should now have handshake keys
    server_crypto = server_connection.instance_variable_get(:@crypto_setup)
    assert server_crypto.available?(:handshake),
      "Server should have handshake keys after receiving ClientHello"
  end

  def test_full_handshake_via_crypto_frames
    client_connection = create_client_connection
    server_connection = create_server_connection

    # 1. Client starts handshake
    client_connection.start_handshake

    # 2. Get client's ClientHello crypto data
    client_crypto = client_connection.instance_variable_get(:@crypto_setup)
    client_hello_data = client_crypto.get_crypto_data(level: :initial)
    refute_nil client_hello_data

    # 3. Server processes ClientHello
    server_tls_adapter = server_connection.instance_variable_get(:@tls_adapter)
    server_tls_adapter.receive_crypto_data(client_hello_data, level: :initial)

    server_crypto = server_connection.instance_variable_get(:@crypto_setup)
    assert server_crypto.available?(:handshake)

    # 4. Get server's response (ServerHello + encrypted flight)
    server_initial_response = server_crypto.get_crypto_data(level: :initial)
    server_handshake_response = server_crypto.get_crypto_data(level: :handshake)

    # 5. Client processes server response
    client_tls_adapter = client_connection.instance_variable_get(:@tls_adapter)

    if server_initial_response && !server_initial_response.empty?
      client_tls_adapter.receive_crypto_data(server_initial_response, level: :initial)
    end

    if server_handshake_response && !server_handshake_response.empty?
      client_tls_adapter.receive_crypto_data(server_handshake_response, level: :handshake)
    end

    # 6. Client should now have handshake and possibly application keys
    assert client_crypto.available?(:handshake),
      "Client should have handshake keys after processing server flight"
  end

  private def create_client_connection
    src_connection_id = Raiha::Quic::Protocol::ConnectionID.generate
    dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate

    Raiha::Connection.new(
      perspective: :client,
      src_connection_id: src_connection_id,
      dest_connection_id: dest_connection_id
    )
  end

  private def create_server_connection
    src_connection_id = Raiha::Quic::Protocol::ConnectionID.generate
    dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate

    Raiha::Connection.new(
      perspective: :server,
      src_connection_id: src_connection_id,
      dest_connection_id: dest_connection_id,
      tls_config: create_server_config
    )
  end
end
