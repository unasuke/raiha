require "test_helper"
require "raiha/quic/handshake/updatable_aead"
require "raiha/tls/cipher_suite"

class RaihaQuicHandshakeUpdatableAEADTest < Minitest::Test
  def test_encrypt_decrypt_roundtrip
    client_aead, server_aead = create_aead_pair

    plaintext = "Hello QUIC 1-RTT".b
    aad = "\x40\x00".b

    encrypted = client_aead.encrypt(plaintext, packet_number: 0, aad: aad)
    decrypted = server_aead.decrypt(encrypted, packet_number: 0, aad: aad)
    assert_equal plaintext, decrypted
  end

  def test_server_to_client
    client_aead, server_aead = create_aead_pair

    plaintext = "Server data".b
    aad = "\x40\x01".b

    encrypted = server_aead.encrypt(plaintext, packet_number: 0, aad: aad)
    decrypted = client_aead.decrypt(encrypted, packet_number: 0, aad: aad)
    assert_equal plaintext, decrypted
  end

  def test_key_rotation
    client_aead, server_aead = create_aead_pair

    refute client_aead.key_phase
    refute server_aead.key_phase

    # Encrypt before rotation
    plaintext = "before rotation".b
    aad = "\x40".b
    encrypted_before = client_aead.encrypt(plaintext, packet_number: 0, aad: aad)

    # Rotate keys on both sides
    client_aead.rotate_keys
    server_aead.rotate_keys

    assert client_aead.key_phase
    assert server_aead.key_phase

    # Encrypt after rotation
    encrypted_after = client_aead.encrypt(plaintext, packet_number: 0, aad: aad)
    refute_equal encrypted_before, encrypted_after

    # Decrypt with rotated keys
    decrypted = server_aead.decrypt(encrypted_after, packet_number: 0, aad: aad)
    assert_equal plaintext, decrypted
  end

  def test_header_protection_mask
    client_aead, _server_aead = create_aead_pair

    sample = "\x00" * 16
    mask = client_aead.header_protection_mask(sample, direction: :send)
    assert_equal 5, mask.bytesize
  end

  def test_sha384_cipher_suite
    cipher_suite = Raiha::TLS::CipherSuite.new(:TLS_AES_256_GCM_SHA384)
    client_secret = OpenSSL::Random.random_bytes(48)
    server_secret = OpenSSL::Random.random_bytes(48)

    client_aead = Raiha::Quic::Handshake::UpdatableAEAD.new(
      client_secret: client_secret, server_secret: server_secret,
      perspective: :client, cipher_suite: cipher_suite
    )
    server_aead = Raiha::Quic::Handshake::UpdatableAEAD.new(
      client_secret: client_secret, server_secret: server_secret,
      perspective: :server, cipher_suite: cipher_suite
    )

    plaintext = "SHA384 test".b
    aad = "\x40".b

    encrypted = client_aead.encrypt(plaintext, packet_number: 0, aad: aad)
    decrypted = server_aead.decrypt(encrypted, packet_number: 0, aad: aad)
    assert_equal plaintext, decrypted
  end

  private def create_aead_pair
    cipher_suite = Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)
    client_secret = OpenSSL::Random.random_bytes(32)
    server_secret = OpenSSL::Random.random_bytes(32)

    client_aead = Raiha::Quic::Handshake::UpdatableAEAD.new(
      client_secret: client_secret, server_secret: server_secret,
      perspective: :client, cipher_suite: cipher_suite
    )
    server_aead = Raiha::Quic::Handshake::UpdatableAEAD.new(
      client_secret: client_secret, server_secret: server_secret,
      perspective: :server, cipher_suite: cipher_suite
    )

    [client_aead, server_aead]
  end
end
