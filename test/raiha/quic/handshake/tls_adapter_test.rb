require "test_helper"
require "raiha/quic/handshake/tls_adapter"
require "raiha/quic/handshake/crypto_setup"
require "raiha/quic/handshake/transport_parameters"
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

  def test_install_early_keys_bridges_tls_secret_into_crypto_setup
    crypto_setup, adapter = create_client

    # Simulate the TLS Client post-PSK state: ClientHello built, early
    # data available, early traffic secret derived.
    tls = adapter.tls
    tls.build_client_hello if tls.client_hello.nil?

    cipher_suite = tls.client_hello.cipher_suites.first
    tls.key_schedule.cipher_suite = cipher_suite
    secret = SecureRandom.random_bytes(
      OpenSSL::Digest.new(cipher_suite.hash_algorithm).digest_length
    )
    tls.key_schedule.instance_variable_set(:@client_early_traffic_secret, secret)
    tls.instance_variable_set(:@early_data_available, true)

    refute crypto_setup.available?(Raiha::Quic::Handshake::EncryptionLevel::ZERO_RTT)
    adapter.send(:install_early_keys_if_available)
    assert crypto_setup.available?(Raiha::Quic::Handshake::EncryptionLevel::ZERO_RTT)
  end

  def test_install_early_keys_is_noop_without_early_data
    crypto_setup, adapter = create_client
    adapter.send(:install_early_keys_if_available)
    refute crypto_setup.available?(Raiha::Quic::Handshake::EncryptionLevel::ZERO_RTT)
  end

  def test_install_early_keys_is_noop_on_server
    crypto_setup, adapter = create_server
    adapter.send(:install_early_keys_if_available)
    refute crypto_setup.available?(Raiha::Quic::Handshake::EncryptionLevel::ZERO_RTT)
  end

  def test_session_ticket_round_trips_transport_parameters
    client_tp = Raiha::Quic::Handshake::TransportParameters.new
    client_tp.initial_max_data = 1_048_576

    server_tp = Raiha::Quic::Handshake::TransportParameters.new
    server_tp.initial_max_data = 524_288
    server_tp.initial_max_stream_data_bidi_local = 65_536

    client_crypto_setup, client_adapter = create_client(transport_parameters: client_tp)
    server_crypto_setup, server_adapter = create_server(transport_parameters: server_tp)

    perform_full_handshake(client_crypto_setup, client_adapter, server_crypto_setup, server_adapter)

    # Server emits NewSessionTicket — the adapter persists local TP as the
    # ticket's application_data (RFC 9001 §4.6.1).
    ticket_handshake_bytes = server_adapter.build_new_session_ticket
    refute_nil ticket_handshake_bytes

    server_store = server_adapter.tls.instance_variable_get(:@session_ticket_store)
    server_entry = server_store.instance_variable_get(:@tickets).values.last
    assert_equal server_tp.serialize, server_entry[:application_data]

    # Client receives NewSessionTicket; adapter attaches peer (server) TP
    # to its own session ticket store entry.
    client_adapter.receive_crypto_data(ticket_handshake_bytes, level: Raiha::Quic::Handshake::EncryptionLevel::ONE_RTT)

    remembered = client_adapter.remembered_transport_parameters
    refute_nil remembered, "client adapter should remember server TP after ticket receipt"
    assert_equal server_tp.initial_max_data, remembered.initial_max_data
    assert_equal server_tp.initial_max_stream_data_bidi_local, remembered.initial_max_stream_data_bidi_local
  end

  def test_remembered_transport_parameters_nil_without_resumption
    _, adapter = create_client
    assert_nil adapter.remembered_transport_parameters
  end

  def test_build_new_session_ticket_returns_nil_for_client
    _, adapter = create_client
    assert_nil adapter.build_new_session_ticket
  end

  private def perform_full_handshake(client_crypto_setup, client_adapter, server_crypto_setup, server_adapter)
    client_adapter.start
    client_hello_data = client_crypto_setup.get_crypto_data(level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    server_adapter.receive_crypto_data(client_hello_data, level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)

    server_initial_data = server_crypto_setup.get_crypto_data(level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    server_handshake_data = server_crypto_setup.get_crypto_data(level: Raiha::Quic::Handshake::EncryptionLevel::HANDSHAKE)

    client_adapter.receive_crypto_data(server_initial_data, level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    client_adapter.receive_crypto_data(server_handshake_data, level: Raiha::Quic::Handshake::EncryptionLevel::HANDSHAKE)

    client_finished_data = client_crypto_setup.get_crypto_data(level: Raiha::Quic::Handshake::EncryptionLevel::HANDSHAKE)
    server_adapter.receive_crypto_data(client_finished_data, level: Raiha::Quic::Handshake::EncryptionLevel::HANDSHAKE)
  end

  private def create_client(transport_parameters: nil)
    connection_id = Raiha::Quic::Protocol::ConnectionID.from_bytes(["0102030405060708"].pack("H*"))
    crypto_setup = Raiha::Quic::Handshake::CryptoSetup.new(
      perspective: :client,
      connection_id: connection_id
    )
    adapter = Raiha::Quic::Handshake::TLSAdapter.new(
      perspective: :client,
      crypto_setup: crypto_setup,
      transport_parameters: transport_parameters
    )
    [crypto_setup, adapter]
  end

  private def create_server(transport_parameters: nil)
    connection_id = Raiha::Quic::Protocol::ConnectionID.from_bytes(["0102030405060708"].pack("H*"))
    crypto_setup = Raiha::Quic::Handshake::CryptoSetup.new(
      perspective: :server,
      connection_id: connection_id
    )
    tls_config = create_server_config
    adapter = Raiha::Quic::Handshake::TLSAdapter.new(
      perspective: :server,
      crypto_setup: crypto_setup,
      tls_config: tls_config,
      transport_parameters: transport_parameters
    )
    [crypto_setup, adapter]
  end
end
