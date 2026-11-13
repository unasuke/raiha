require "test_helper"
require "raiha/tls"

class RaihaNextTLSHandshakeKeyUpdateTest < Minitest::Test
  TLS = Raiha::Next::TLS
  REGISTRY = TLS::Extension::Registry::BUILTIN

  def test_parse_and_encode
    ku = TLS::Handshake.parse("\x18\x00\x00\x01\x01".b, registry: REGISTRY)
    assert_instance_of TLS::Handshake::KeyUpdate, ku
    assert_equal 24, ku.msg_type
    assert_equal TLS::Handshake::KeyUpdate::UPDATE_REQUESTED, ku.request_update
    assert_equal_bin "\x18\x00\x00\x01\x01".b, ku.encode
  end

  def test_any_request_update_value_parses
    assert_equal 2, TLS::Handshake.parse("\x18\x00\x00\x01\x02".b, registry: REGISTRY).request_update
  end

  def test_wrong_length
    assert_raises(TLS::Codec::Truncated) { TLS::Handshake.parse("\x18\x00\x00\x00".b, registry: REGISTRY) }
    assert_raises(TLS::Codec::TrailingData) { TLS::Handshake.parse("\x18\x00\x00\x02\x00\x00".b, registry: REGISTRY) }
  end
end
