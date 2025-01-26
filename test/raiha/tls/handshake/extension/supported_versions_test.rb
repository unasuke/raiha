require "test_helper"
require "raiha/tls/handshake/extension"

class RaihaTLSHandshakeExtensionSupportedVersionsTest < Minitest::Test
  def test_generate_for_tls13
    ext = Raiha::TLS::Handshake::Extension::SupportedVersions.generate_for_tls13
    assert_equal Raiha::TLS::Handshake::Extension::SupportedVersions, ext.class
    assert_equal "\x02\x03\x04", ext.extension_data
  end

  def test_serialize
    ext = Raiha::TLS::Handshake::Extension::SupportedVersions.generate_for_tls13
    assert_equal "\x00\x2b\x00\x03\x02\x03\x04", ext.serialize
  end
end
