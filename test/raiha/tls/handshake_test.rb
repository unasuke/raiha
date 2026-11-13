require "test_helper"
require "raiha/tls/test"

class RaihaTLSHandshakeTest < Minitest::Test
  TLS = Raiha::TLS
  Codec = TLS::Codec
  REGISTRY = TLS::Extension::Registry::BUILTIN
  CLIENT_HELLO = TLS::Test::RFC8448::Simple1RTT::CLIENT_HELLO

  def test_message_hash_is_listed_but_never_parsed
    assert_equal :message_hash, TLS::Handshake::TYPES[254]
    assert_raises(Codec::UnknownMessageType) { TLS::Handshake.parse("\xfe\x00\x00\x00".b, registry: REGISTRY) }
  end

  def test_unknown_message_type
    error = assert_raises(Codec::UnknownMessageType) { TLS::Handshake.parse("\x63\x00\x00\x00".b, registry: REGISTRY) }
    assert_equal :unexpected_message, error.alert
  end

  def test_bytes_after_the_message
    assert_raises(Codec::TrailingData) { TLS::Handshake.parse(CLIENT_HELLO + "\x00".b, registry: REGISTRY) }
  end

  def test_message_shorter_than_its_length
    assert_raises(Codec::Truncated) { TLS::Handshake.parse(CLIENT_HELLO.byteslice(0, 100), registry: REGISTRY) }
    assert_raises(Codec::Truncated) { TLS::Handshake.parse("\x01\x00".b, registry: REGISTRY) }
  end

  def test_parse_body_takes_the_body_alone
    ch = TLS::Handshake.parse_body(1, CLIENT_HELLO.byteslice(4..), registry: REGISTRY)
    assert_equal_bin CLIENT_HELLO, ch.encode
  end
end
