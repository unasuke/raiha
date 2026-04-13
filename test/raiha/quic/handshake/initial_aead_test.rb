require "test_helper"
require "raiha/quic/handshake/initial_aead"
require "raiha/quic/protocol/connection_id"

class RaihaQuicHandshakeInitialAEADTest < Minitest::Test
  # RFC 9001 Appendix A - Initial Keys
  # DESTINATION_CONNECTION_ID = 0x8394c8f03e515708
  DESTINATION_CONNECTION_ID = Raiha::Quic::Protocol::ConnectionID.from_bytes(
    ["8394c8f03e515708"].pack("H*")
  )

  def test_derive_client_initial_key
    client_aead = Raiha::Quic::Handshake::InitialAEAD.new(
      connection_id: DESTINATION_CONNECTION_ID,
      perspective: :client
    )
    server_aead = Raiha::Quic::Handshake::InitialAEAD.new(
      connection_id: DESTINATION_CONNECTION_ID,
      perspective: :server
    )

    # Client encrypts with client key, server decrypts with client key
    plaintext = "Hello QUIC".b
    aad = "\xc0\x00\x00\x01".b

    encrypted = client_aead.encrypt(plaintext, packet_number: 0, aad: aad)
    decrypted = server_aead.decrypt(encrypted, packet_number: 0, aad: aad)
    assert_equal plaintext, decrypted
  end

  def test_derive_server_initial_key
    server_aead = Raiha::Quic::Handshake::InitialAEAD.new(
      connection_id: DESTINATION_CONNECTION_ID,
      perspective: :server
    )
    client_aead = Raiha::Quic::Handshake::InitialAEAD.new(
      connection_id: DESTINATION_CONNECTION_ID,
      perspective: :client
    )

    # Server encrypts with server key, client decrypts with server key
    plaintext = "Server response".b
    aad = "\xc1\x00\x00\x01".b

    encrypted = server_aead.encrypt(plaintext, packet_number: 0, aad: aad)
    decrypted = client_aead.decrypt(encrypted, packet_number: 0, aad: aad)
    assert_equal plaintext, decrypted
  end

  def test_client_server_interop
    client_aead = Raiha::Quic::Handshake::InitialAEAD.new(
      connection_id: DESTINATION_CONNECTION_ID,
      perspective: :client
    )
    server_aead = Raiha::Quic::Handshake::InitialAEAD.new(
      connection_id: DESTINATION_CONNECTION_ID,
      perspective: :server
    )

    # Client encrypts, server decrypts
    plaintext = "Client to Server".b
    aad = "\xc0\x00\x00\x01".b

    encrypted = client_aead.encrypt(plaintext, packet_number: 0, aad: aad)
    decrypted = server_aead.decrypt(encrypted, packet_number: 0, aad: aad)
    assert_equal plaintext, decrypted

    # Server encrypts, client decrypts
    server_plaintext = "Server to Client".b
    server_aad = "\xc1\x00\x00\x01".b

    server_encrypted = server_aead.encrypt(server_plaintext, packet_number: 0, aad: server_aad)
    server_decrypted = client_aead.decrypt(server_encrypted, packet_number: 0, aad: server_aad)
    assert_equal server_plaintext, server_decrypted
  end

  def test_header_protection_mask
    aead = Raiha::Quic::Handshake::InitialAEAD.new(
      connection_id: DESTINATION_CONNECTION_ID,
      perspective: :client
    )

    sample = "\x00" * 16
    mask = aead.header_protection_mask(sample, direction: :send)
    assert_equal 5, mask.bytesize
  end

  def test_packet_number_affects_nonce
    aead = Raiha::Quic::Handshake::InitialAEAD.new(
      connection_id: DESTINATION_CONNECTION_ID,
      perspective: :client
    )

    plaintext = "test".b
    aad = "\xc0".b

    encrypted_0 = aead.encrypt(plaintext, packet_number: 0, aad: aad)
    encrypted_1 = aead.encrypt(plaintext, packet_number: 1, aad: aad)

    # Different packet numbers should produce different ciphertext
    refute_equal encrypted_0, encrypted_1
  end

  def test_v2_salt
    aead_v1 = Raiha::Quic::Handshake::InitialAEAD.new(
      connection_id: DESTINATION_CONNECTION_ID,
      perspective: :client,
      version: Raiha::Quic::Protocol::Version::V1
    )
    aead_v2 = Raiha::Quic::Handshake::InitialAEAD.new(
      connection_id: DESTINATION_CONNECTION_ID,
      perspective: :client,
      version: Raiha::Quic::Protocol::Version::V2
    )

    plaintext = "test".b
    aad = "\xc0".b

    # v1 and v2 should produce different keys (different salts)
    encrypted_v1 = aead_v1.encrypt(plaintext, packet_number: 0, aad: aad)
    encrypted_v2 = aead_v2.encrypt(plaintext, packet_number: 0, aad: aad)
    refute_equal encrypted_v1, encrypted_v2
  end
end
