require "test_helper"
require "support/rfc8448_test_vector"
require "raiha/tls/handshake"
require "raiha/tls/cipher_suite"

class RaihaTLSHandShakeTest < Minitest::Test
  def test_serialize_client_hello
    hs = ::Raiha::TLS::Handshake.new.tap do |hs|
      hs.handshake_type = ::Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
      hs.message = ::Raiha::TLS::Handshake::ClientHello.build
    end
    hs.message.random = RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO_RANDOM
    # TODO: Build ClientHello extentions
    # assert_equal_bin RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO, hs.serialize
  end

  def test_deserialize_client_hello
    hs = ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO)
    assert_equal 192, hs.length
    assert_equal ::Raiha::TLS::Handshake::ClientHello, hs.message.class
    assert_equal RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO_RANDOM, hs.message.random
    assert_equal 3, hs.message.cipher_suites.size
    assert_equal 9, hs.message.extensions.size
  end

  def test_deserialize_wrong_length_bytes
    too_long_hs = ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO + "\x00")
    assert_nil too_long_hs
    too_short_hs = ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO[0..-2])
    assert_nil too_short_hs
  end

  def test_deserialize_multiple
    handshakes = ::Raiha::TLS::Handshake.deserialize_multiple(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO + RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
    assert_equal 2, handshakes.size
    assert_equal ::Raiha::TLS::Handshake::ClientHello, handshakes[0].message.class
    assert_equal ::Raiha::TLS::Handshake::ServerHello, handshakes[1].message.class
  end

  def test_deserialize_with_bytes_returns_handshake_and_raw_bytes
    result = ::Raiha::TLS::Handshake.deserialize_with_bytes(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO)
    refute_nil result
    hs, raw_bytes = result
    assert_equal ::Raiha::TLS::Handshake::ClientHello, hs.message.class
    assert_equal 192, hs.length
    assert_equal RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO, raw_bytes
  end

  def test_deserialize_with_bytes_returns_nil_on_wrong_length
    too_long = ::Raiha::TLS::Handshake.deserialize_with_bytes(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO + "\x00")
    assert_nil too_long
    too_short = ::Raiha::TLS::Handshake.deserialize_with_bytes(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO[0..-2])
    assert_nil too_short
  end

  def test_deserialize_multiple_with_bytes_returns_pairs
    concatenated = RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO + RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO
    pairs = ::Raiha::TLS::Handshake.deserialize_multiple_with_bytes(concatenated)
    assert_equal 2, pairs.size
    ch_hs, ch_bytes = pairs[0]
    sh_hs, sh_bytes = pairs[1]
    assert_equal ::Raiha::TLS::Handshake::ClientHello, ch_hs.message.class
    assert_equal RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO, ch_bytes
    assert_equal ::Raiha::TLS::Handshake::ServerHello, sh_hs.message.class
    assert_equal RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO, sh_bytes
  end
end
