require "test_helper"
require "raiha/tls/handshake"

class RaihaTLSHandshakeServerHelloTest < Minitest::Test
  # https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO = [<<~SH.gsub(/[[:space:]]/, '')].pack("H*")
    02 00 00 56 03 03 a6 af 06 a4 12 18 60
    dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
    d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88
    76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1
    dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04
  SH

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
