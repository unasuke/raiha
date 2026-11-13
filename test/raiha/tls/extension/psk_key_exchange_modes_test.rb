require "test_helper"
require "raiha/tls"

class RaihaNextTLSExtensionPskKeyExchangeModesTest < Minitest::Test
  Codec = Raiha::Next::TLS::Codec
  PskKeyExchangeModes = Raiha::Next::TLS::Extension::PskKeyExchangeModes

  def test_parse_and_encode
    ext = PskKeyExchangeModes.parse("\x01\x01".b)
    assert_equal [1], ext.ke_modes
    assert_equal 45, ext.extension_type
    assert_equal_bin "\x01\x01".b, ext.encode
  end

  def test_bounds
    assert_raises(Codec::RangeViolation) { PskKeyExchangeModes.parse("\x00".b) }
    assert_raises(Codec::EncodeError) { PskKeyExchangeModes.new(ke_modes: []).encode }
  end
end
