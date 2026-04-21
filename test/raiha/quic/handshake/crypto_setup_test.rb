require "test_helper"
require "raiha/quic/handshake/crypto_setup"
require "raiha/tls/cipher_suite"

class RaihaQuicHandshakeCryptoSetupTest < Minitest::Test
  def test_initial_state
    crypto_setup = create_crypto_setup(:client)

    assert crypto_setup.available?(Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    refute crypto_setup.available?(Raiha::Quic::Handshake::EncryptionLevel::HANDSHAKE)
    refute crypto_setup.available?(Raiha::Quic::Handshake::EncryptionLevel::ONE_RTT)
    refute crypto_setup.handshake_complete?
  end

  def test_initial_encrypt_decrypt
    client_setup = create_crypto_setup(:client)
    server_setup = create_crypto_setup(:server)

    level = Raiha::Quic::Handshake::EncryptionLevel::INITIAL
    plaintext = "ClientHello data".b
    aad = "\xc0\x00\x00\x01\x08".b

    encrypted = client_setup.encrypt(plaintext, packet_number: 0, aad: aad, level: level)
    decrypted = server_setup.decrypt(encrypted, packet_number: 0, aad: aad, level: level)
    assert_equal plaintext, decrypted
  end

  def test_set_handshake_keys
    crypto_setup = create_crypto_setup(:client)
    cipher_suite = Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)

    refute crypto_setup.available?(Raiha::Quic::Handshake::EncryptionLevel::HANDSHAKE)

    crypto_setup.set_handshake_keys(
      client_secret: OpenSSL::Random.random_bytes(32),
      server_secret: OpenSSL::Random.random_bytes(32),
      cipher_suite: cipher_suite
    )

    assert crypto_setup.available?(Raiha::Quic::Handshake::EncryptionLevel::HANDSHAKE)
    refute crypto_setup.handshake_complete?
  end

  def test_set_application_keys_completes_handshake
    crypto_setup = create_crypto_setup(:client)
    cipher_suite = Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)

    crypto_setup.set_application_keys(
      client_secret: OpenSSL::Random.random_bytes(32),
      server_secret: OpenSSL::Random.random_bytes(32),
      cipher_suite: cipher_suite
    )

    assert crypto_setup.available?(Raiha::Quic::Handshake::EncryptionLevel::ONE_RTT)
    assert crypto_setup.handshake_complete?
  end

  def test_handshake_encrypt_decrypt
    client_secret = OpenSSL::Random.random_bytes(32)
    server_secret = OpenSSL::Random.random_bytes(32)
    cipher_suite = Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)

    client_setup = create_crypto_setup(:client)
    server_setup = create_crypto_setup(:server)

    client_setup.set_handshake_keys(client_secret: client_secret, server_secret: server_secret, cipher_suite: cipher_suite)
    server_setup.set_handshake_keys(client_secret: client_secret, server_secret: server_secret, cipher_suite: cipher_suite)

    level = Raiha::Quic::Handshake::EncryptionLevel::HANDSHAKE
    plaintext = "Handshake data".b
    aad = "\xc0\x00\x00\x01".b

    encrypted = client_setup.encrypt(plaintext, packet_number: 0, aad: aad, level: level)
    decrypted = server_setup.decrypt(encrypted, packet_number: 0, aad: aad, level: level)
    assert_equal plaintext, decrypted
  end

  def test_one_rtt_encrypt_decrypt
    client_secret = OpenSSL::Random.random_bytes(32)
    server_secret = OpenSSL::Random.random_bytes(32)
    cipher_suite = Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)

    client_setup = create_crypto_setup(:client)
    server_setup = create_crypto_setup(:server)

    client_setup.set_application_keys(client_secret: client_secret, server_secret: server_secret, cipher_suite: cipher_suite)
    server_setup.set_application_keys(client_secret: client_secret, server_secret: server_secret, cipher_suite: cipher_suite)

    level = Raiha::Quic::Handshake::EncryptionLevel::ONE_RTT
    plaintext = "Application data".b
    aad = "\x40\x00".b

    encrypted = client_setup.encrypt(plaintext, packet_number: 0, aad: aad, level: level)
    decrypted = server_setup.decrypt(encrypted, packet_number: 0, aad: aad, level: level)
    assert_equal plaintext, decrypted
  end

  def test_header_protection_mask
    crypto_setup = create_crypto_setup(:client)
    sample = "\x00" * 16

    mask = crypto_setup.header_protection_mask(sample, level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL, direction: :send)
    assert_equal 5, mask.bytesize
  end

  def test_discard_initial_keys
    crypto_setup = create_crypto_setup(:client)
    assert crypto_setup.available?(Raiha::Quic::Handshake::EncryptionLevel::INITIAL)

    crypto_setup.discard_keys(Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    refute crypto_setup.available?(Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
  end

  def test_crypto_data_queue
    crypto_setup = create_crypto_setup(:client)

    assert_nil crypto_setup.get_crypto_data(level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)

    crypto_setup.queue_crypto_data("hello".b, level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    crypto_setup.queue_crypto_data(" world".b, level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)

    data = crypto_setup.get_crypto_data(level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    assert_equal "hello world".b, data

    # Queue is now empty
    assert_nil crypto_setup.get_crypto_data(level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
  end

  def test_pop_crypto_frame_returns_chunks_with_contiguous_offsets
    crypto_setup = create_crypto_setup(:client)
    level = Raiha::Quic::Handshake::EncryptionLevel::INITIAL

    crypto_setup.queue_crypto_data("hello".b, level: level)
    crypto_setup.queue_crypto_data(" world".b, level: level)

    first = crypto_setup.pop_crypto_frame(level: level)
    assert_equal 0, first[:offset]
    assert_equal "hello".b, first[:data]

    second = crypto_setup.pop_crypto_frame(level: level)
    assert_equal 5, second[:offset]
    assert_equal " world".b, second[:data]

    assert_nil crypto_setup.pop_crypto_frame(level: level)
  end

  def test_requeue_crypto_data_preserves_original_offset
    crypto_setup = create_crypto_setup(:client)
    level = Raiha::Quic::Handshake::EncryptionLevel::INITIAL

    crypto_setup.queue_crypto_data("ABCDE".b, level: level)
    first = crypto_setup.pop_crypto_frame(level: level)

    # Simulate loss: requeue the dequeued chunk at its original offset.
    crypto_setup.requeue_crypto_data(offset: first[:offset], data: first[:data], level: level)

    # New data arrives after the lost chunk.
    crypto_setup.queue_crypto_data("FG".b, level: level)

    re_emitted = crypto_setup.pop_crypto_frame(level: level)
    assert_equal 0, re_emitted[:offset]
    assert_equal "ABCDE".b, re_emitted[:data]

    fresh = crypto_setup.pop_crypto_frame(level: level)
    assert_equal 5, fresh[:offset]
    assert_equal "FG".b, fresh[:data]
  end

  def test_key_update
    client_secret = OpenSSL::Random.random_bytes(32)
    server_secret = OpenSSL::Random.random_bytes(32)
    cipher_suite = Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)

    client_setup = create_crypto_setup(:client)
    server_setup = create_crypto_setup(:server)

    client_setup.set_application_keys(client_secret: client_secret, server_secret: server_secret, cipher_suite: cipher_suite)
    server_setup.set_application_keys(client_secret: client_secret, server_secret: server_secret, cipher_suite: cipher_suite)

    level = Raiha::Quic::Handshake::EncryptionLevel::ONE_RTT
    plaintext = "before update".b
    aad = "\x40".b

    encrypted_before = client_setup.encrypt(plaintext, packet_number: 0, aad: aad, level: level)

    client_setup.update_keys
    server_setup.update_keys

    encrypted_after = client_setup.encrypt(plaintext, packet_number: 0, aad: aad, level: level)
    refute_equal encrypted_before, encrypted_after

    decrypted = server_setup.decrypt(encrypted_after, packet_number: 0, aad: aad, level: level)
    assert_equal plaintext, decrypted
  end

  def test_encrypt_unavailable_level_raises
    crypto_setup = create_crypto_setup(:client)

    assert_raises(Raiha::Quic::Error) do
      crypto_setup.encrypt("data".b, packet_number: 0, aad: "".b, level: Raiha::Quic::Handshake::EncryptionLevel::HANDSHAKE)
    end
  end

  private def create_crypto_setup(perspective)
    connection_id = Raiha::Quic::Protocol::ConnectionID.from_bytes(
      ["8394c8f03e515708"].pack("H*")
    )
    Raiha::Quic::Handshake::CryptoSetup.new(
      perspective: perspective,
      connection_id: connection_id
    )
  end
end
