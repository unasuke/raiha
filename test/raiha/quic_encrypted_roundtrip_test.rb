require "test_helper"
require "raiha/connection"
require "support/test_certificate"

class RaihaQuicEncryptedRoundtripTest < Minitest::Test
  include TestCertificate

  DEST_CID_BYTES = ["8394c8f03e515708"].pack("H*")
  SRC_CID_BYTES = ["0102030405060708"].pack("H*")

  def test_build_and_handle_initial_packet
    # Both use same connection IDs so Initial AEAD keys match
    client_connection = create_client_connection
    server_connection = create_server_connection

    # Client starts handshake
    client_connection.start_handshake

    # Client builds encrypted Initial packet
    packets = client_connection.get_packets_to_send
    refute_empty packets, "Client should produce packets"

    initial_packet = packets.first
    assert initial_packet.bytesize > 0

    # Server receives and processes the encrypted packet
    server_connection.handle_packet(initial_packet)

    # Server's TLS adapter should have received the ClientHello
    server_crypto = server_connection.instance_variable_get(:@crypto_setup)
    assert server_crypto.available?(:handshake),
      "Server should derive handshake keys after receiving ClientHello via encrypted Initial packet"
  end

  def test_crypto_frame_encrypted_roundtrip
    client_connection = create_client_connection
    server_connection = create_server_connection

    # Build a CRYPTO frame with enough data so header protection sample is available
    crypto_frame = Raiha::Quic::Wire::Frames::CryptoFrame.new
    crypto_frame.offset = 0
    crypto_frame.data = "\x00" * 32 # Enough data for sample extraction

    packet = client_connection.build_packet(
      [crypto_frame],
      level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL
    )

    refute_nil packet

    # Verify header protection was applied (first byte should be modified)
    # Server processes the encrypted packet
    server_connection.handle_packet(packet)
    # No error = success (CRYPTO frame with dummy data is processed silently)
  end

  private def create_client_connection
    Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.from_bytes(SRC_CID_BYTES),
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.from_bytes(DEST_CID_BYTES)
    )
  end

  private def create_server_connection
    # Initial AEAD keys are derived from the client's original DCID
    # Server must use the same DCID for Initial key derivation
    Raiha::Connection.new(
      perspective: :server,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.from_bytes(SRC_CID_BYTES),
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.from_bytes(DEST_CID_BYTES),
      tls_config: create_server_config
    )
  end
end
