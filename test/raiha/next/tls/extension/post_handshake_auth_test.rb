require "raiha/next/test_helper"
require "raiha/next/tls"

class RaihaNextTLSExtensionPostHandshakeAuthTest < Minitest::Test
  Codec = Raiha::Next::TLS::Codec
  PostHandshakeAuth = Raiha::Next::TLS::Extension::PostHandshakeAuth

  def test_is_empty
    ext = PostHandshakeAuth.parse("".b)
    assert_equal 49, ext.extension_type
    assert_equal "".b, ext.encode
    assert_raises(Codec::TrailingData) { PostHandshakeAuth.parse("\x00".b) }
  end
end
