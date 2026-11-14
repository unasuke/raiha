require "test_helper"
require "raiha/tls"

class RaihaTLSExtensionCookieTest < Minitest::Test
  Codec = Raiha::TLS::Codec
  Cookie = Raiha::TLS::Extension::Cookie

  def test_parse_and_encode
    ext = Cookie.parse("\x00\x03abc".b)
    assert_equal "abc".b, ext.cookie
    assert_equal 44, ext.extension_type
    assert_equal_bin "\x00\x03abc".b, ext.encode
    assert Ractor.shareable?(ext)
  end

  def test_bounds
    assert_raises(Codec::RangeViolation) { Cookie.parse("\x00\x00".b) }
    assert_raises(Codec::EncodeError) { Cookie.new(cookie: "".b).encode }
  end
end
