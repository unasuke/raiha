require "test_helper"
require "raiha/quic/handshake/tls_adapter"
require "raiha/quic/handshake/crypto_setup"
require "raiha/quic/protocol/connection_id"
require "support/test_certificate"

class RaihaQuicHandshakeTLSAdapterTest < Minitest::Test
  include TestCertificate

  def test_client_start_produces_crypto_data
    client_crypto_setup, client_adapter = create_client

    client_adapter.start

    crypto_data = client_crypto_setup.get_crypto_data(level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    refute_nil crypto_data
    assert crypto_data.bytesize > 0

    # Should be a ClientHello handshake message (type 0x01)
    assert_equal 1, crypto_data.getbyte(0), "First byte should be ClientHello type (0x01)"
  end

  def test_server_receives_client_hello
    client_crypto_setup, client_adapter = create_client
    server_crypto_setup, server_adapter = create_server

    # Client generates ClientHello
    client_adapter.start
    client_hello_data = client_crypto_setup.get_crypto_data(level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)

    # Server processes ClientHello
    server_adapter.receive_crypto_data(client_hello_data, level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)

    # Server should have handshake keys now
    assert server_crypto_setup.available?(Raiha::Quic::Handshake::EncryptionLevel::HANDSHAKE),
      "Server should have handshake keys after processing ClientHello"
  end

  def test_full_handshake
    client_crypto_setup, client_adapter = create_client
    server_crypto_setup, server_adapter = create_server

    # 1. Client sends ClientHello
    client_adapter.start
    client_hello_data = client_crypto_setup.get_crypto_data(level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    refute_nil client_hello_data

    # 2. Server processes ClientHello, produces ServerHello + flight
    server_adapter.receive_crypto_data(client_hello_data, level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    assert server_crypto_setup.available?(Raiha::Quic::Handshake::EncryptionLevel::HANDSHAKE),
      "Server should have handshake keys"

    server_initial_data = server_crypto_setup.get_crypto_data(level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    server_handshake_data = server_crypto_setup.get_crypto_data(level: Raiha::Quic::Handshake::EncryptionLevel::HANDSHAKE)

    refute_nil server_initial_data, "Server should produce ServerHello at Initial level"
    refute_nil server_handshake_data, "Server should produce encrypted flight at Handshake level"

    # 3. Client processes ServerHello (Initial level)
    client_adapter.receive_crypto_data(server_initial_data, level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    assert client_crypto_setup.available?(Raiha::Quic::Handshake::EncryptionLevel::HANDSHAKE),
      "Client should have handshake keys after ServerHello"

    # 4. Client processes EE + Cert + CertVerify + Finished (Handshake level)
    client_adapter.receive_crypto_data(server_handshake_data, level: Raiha::Quic::Handshake::EncryptionLevel::HANDSHAKE)
    assert client_crypto_setup.available?(Raiha::Quic::Handshake::EncryptionLevel::ONE_RTT),
      "Client should have application keys after server Finished"

    # 5. Client should have produced Finished at Handshake level
    client_finished_data = client_crypto_setup.get_crypto_data(level: Raiha::Quic::Handshake::EncryptionLevel::HANDSHAKE)
    refute_nil client_finished_data, "Client should produce Finished at Handshake level"

    # 6. Server processes client Finished
    server_adapter.receive_crypto_data(client_finished_data, level: Raiha::Quic::Handshake::EncryptionLevel::HANDSHAKE)

    # Both sides should have completed the handshake
    assert client_crypto_setup.handshake_complete?, "Client handshake should be complete"
    assert server_crypto_setup.handshake_complete?, "Server handshake should be complete"
  end

  private def create_client
    connection_id = Raiha::Quic::Protocol::ConnectionID.from_bytes(["0102030405060708"].pack("H*"))
    crypto_setup = Raiha::Quic::Handshake::CryptoSetup.new(
      perspective: :client,
      connection_id: connection_id
    )
    adapter = Raiha::Quic::Handshake::TLSAdapter.new(
      perspective: :client,
      crypto_setup: crypto_setup
    )
    [crypto_setup, adapter]
  end

  private def create_server
    connection_id = Raiha::Quic::Protocol::ConnectionID.from_bytes(["0102030405060708"].pack("H*"))
    crypto_setup = Raiha::Quic::Handshake::CryptoSetup.new(
      perspective: :server,
      connection_id: connection_id
    )
    tls_config = create_server_config
    adapter = Raiha::Quic::Handshake::TLSAdapter.new(
      perspective: :server,
      crypto_setup: crypto_setup,
      tls_config: tls_config
    )
    [crypto_setup, adapter]
  end
end
