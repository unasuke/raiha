require "test_helper"
require "raiha/tls/handshake"
require "raiha/tls/cipher_suite"

# https://datatracker.ietf.org/doc/html/rfc8448#section-3
RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO = [<<~HS.gsub(/[[:space:]]/, '')].pack("H*")
  01 00 00 c0 03 03 cb 34 ec b1 e7 81 63
  ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83
  02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b
  00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00
  12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23
  00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2
  3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a
  af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
  02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06
  02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01
HS

# https://datatracker.ietf.org/doc/html/rfc8448#section-3
RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO_RANDOM = [<<~RANDOM.gsub(/[[:space:]]/, '')].pack("H*")
  cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d
  ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7
RANDOM

# https://datatracker.ietf.org/doc/html/rfc8448#section-3
RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO = [<<~SH.gsub(/[[:space:]]/, '')].pack("H*")
  02 00 00 56 03 03 a6 af 06 a4 12 18 60
  dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
  d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88
  76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1
  dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04
SH

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
end
