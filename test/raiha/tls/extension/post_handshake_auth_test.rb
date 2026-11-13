require "test_helper"
require "raiha/tls"

class RaihaTLSExtensionPostHandshakeAuthTest < Minitest::Test
  Codec = Raiha::TLS::Codec
  PostHandshakeAuth = Raiha::TLS::Extension::PostHandshakeAuth

  def test_is_empty
    ext = PostHandshakeAuth.parse("".b)
    assert_equal 49, ext.extension_type
    assert_equal "".b, ext.encode
    assert_raises(Codec::TrailingData) { PostHandshakeAuth.parse("\x00".b) }
  end
end
