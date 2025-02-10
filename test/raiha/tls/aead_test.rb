require "test_helper"
require "support/rfc8448_test_vector"
require "raiha/tls/aead"
require "raiha/tls/handshake"

class RaihaTLSAEADTest < Minitest::Test
  def setup
    setup_key_schedule
  end

  def test_decrypt
    aead = Raiha::TLS::AEAD.new(cipher_suite: @cipher_suite, key_schedule: @key_schedule)
    aead.mode = :server
    record = Raiha::TLS::Record.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_PROTECTED_RECORD).first
    plain = aead.decrypt(ciphertext: record, phase: :handshake)
    whole_expected_message =
      RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_ENCRYPTED_EXTENSIONS +
      RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE +
      RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE_VERIFY +
      RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_FINISHED
    assert_equal whole_expected_message.bytesize, plain.content.bytesize
    assert_equal_bin whole_expected_message, plain.content
  end

  def test_encrypt
    aead = Raiha::TLS::AEAD.new(cipher_suite: @cipher_suite, key_schedule: @key_schedule)
    aead.mode = :client
    handshake_finished = Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_FINISHED)
    plaintext = Raiha::TLS::Record::TLSInnerPlaintext.new.tap do |inner|
      inner.content = handshake_finished.serialize # double serialize ;)
      inner.content_type = Raiha::TLS::Record::CONTENT_TYPE[:handshake]
    end
    ciphertext = aead.encrypt(plaintext: plaintext, phase: :handshake)
    assert_equal_bin RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_FINISHED_PROTECTED, ciphertext.serialize
  end

  private def setup_key_schedule
    @key_schedule = Raiha::TLS::KeySchedule.new(mode: :server).tap do |ks|
      ks.cipher_suite = ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)
      ks.pkey = OpenSSL::PKey.new_raw_private_key("x25519", RFC8448_SIMPLE_1RTT_SERVER_EPHEMERAL_X25519_PRIVATE_KEY)
      ks.group = "x25519"
      ks.public_key = RFC8448_SIMPLE_1RTT_CLIENT_EPHEMERAL_X25519_PUBLIC_KEY
      ks.compute_shared_secret
      ks.derive_secret(secret: :early_secret, label: "derived", messages: [""])
      ks.derive_client_handshake_traffic_secret([
        ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO),
        ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
      ])
      ks.derive_server_handshake_traffic_secret([
        ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO),
        ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
      ])
    end
    @cipher_suite = Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)
  end
end
