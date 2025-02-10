require "test_helper"
require "support/rfc8448_test_vector"
require "raiha/tls/handshake"

class RaihaTLSHandshakeServerHelloTest < Minitest::Test
  def test_build_from_client_hello
    ch = Raiha::TLS::Handshake::ClientHello.build
    sh = Raiha::TLS::Handshake::ServerHello.build_from_client_hello(ch)
    assert_equal Raiha::TLS::Handshake::ServerHello, sh.class
    refute_equal ch.random, sh.random
    assert_equal ch.legacy_session_id, sh.legacy_session_id_echo
    assert_equal Raiha::TLS::CipherSuite, sh.cipher_suite.class
    assert sh.cipher_suite.supported?
    assert_equal 1, sh.extensions.length
  end

  def test_deserialize
    skip
    sh_original = Raiha::TLS::Handshake::ServerHello.build_from_client_hello(Raiha::TLS::Handshake::ClientHello.build)
    sh_deserialized = Raiha::TLS::Handshake::ServerHello.deserialize(sh_original.serialize)
    assert_equal sh_original.class, sh_deserialized.class
    assert_equal sh_original.random, sh_deserialized.random
    assert_equal sh_original.legacy_session_id_echo, sh_deserialized.legacy_session_id_echo
    assert_equal sh_original.cipher_suite.value, sh_deserialized.cipher_suite.value
    assert_equal sh_original.extensions.length, sh_deserialized.extensions.length
  end

  def test_serialize_rfc8448_simple_1rtt_handshake_server_hello
    sh = Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
    assert_equal_bin RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO, sh.serialize
  end

  def test_hello_retry_request?
    sh1 = Raiha::TLS::Handshake::ServerHello.new.tap do |sh|
      sh.random = Raiha::TLS::Handshake::ServerHello::HELLO_RETRY_REQUEST_RANDOM
    end
    assert_equal true, sh1.hello_retry_request?

    sh2 = Raiha::TLS::Handshake::ServerHello.new.tap do |sh|
      loop do
        sh.random = SecureRandom.random_bytes(32)
        break if sh.random != Raiha::TLS::Handshake::ServerHello::HELLO_RETRY_REQUEST_RANDOM
      end
    end
    assert_equal false, sh2.hello_retry_request?
  end
end
