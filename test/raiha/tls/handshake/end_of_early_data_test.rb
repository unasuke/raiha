require "test_helper"
require "raiha/tls"

class RaihaNextTLSHandshakeEndOfEarlyDataTest < Minitest::Test
  TLS = Raiha::TLS
  REGISTRY = TLS::Extension::Registry::BUILTIN

  # From RFC 8448 section 4.
  def test_parse_and_encode
    eoed = TLS::Handshake.parse("\x05\x00\x00\x00".b, registry: REGISTRY)
    assert_instance_of TLS::Handshake::EndOfEarlyData, eoed
    assert_equal 5, eoed.msg_type
    assert_equal_bin "\x05\x00\x00\x00".b, eoed.encode
  end

  def test_body_must_be_empty
    assert_raises(TLS::Codec::TrailingData) { TLS::Handshake.parse("\x05\x00\x00\x01\x00".b, registry: REGISTRY) }
  end
end
