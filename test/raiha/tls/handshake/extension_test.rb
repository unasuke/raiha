require "test_helper"
require "raiha/tls/handshake/extension"

class RaihaTLSHandshakeExtensionTest < Minitest::Test
  def test_serialize
    ext1 = Raiha::TLS::Handshake::Extension.new.tap do |ext|
      ext.extension_type = Raiha::TLS::Handshake::Extension::EXTENSION_TYPE[:supported_versions]
      ext.extension_data = [0x03, 0x04] # TLS13_SUPPORTED_VERSION
    end
    assert_equal "\x00\x2b\x00\x02\x03\x04", ext1.serialize

    ext2 = Raiha::TLS::Handshake::Extension.new.tap do |ext|
      ext.extension_type = Raiha::TLS::Handshake::Extension::EXTENSION_TYPE[:supported_groups]
      ext.extension_data = [0x03, 0x04]
    end
    assert_equal "\x00\x0a\x00\x02\x03\x04", ext2.serialize

    ext3 = Raiha::TLS::Handshake::Extension.new.tap do |ext|
      ext.extension_type = Raiha::TLS::Handshake::Extension::EXTENSION_TYPE[:signature_algorithms]
      ext.extension_data = [0x03, 0x04]
    end
    assert_equal "\x00\x0d\x00\x02\x03\x04", ext3.serialize
  end

  def test_deserialize_extensions
    exts = "\x00\x2b\x00\x02\x03\x04\x00\x0a\x00\x02\x03\x04\x00\x0d\x00\x02\x03\x04"
    extensions = Raiha::TLS::Handshake::Extension.deserialize_extensions(exts, type: :client_hello)
    assert_equal Raiha::TLS::Handshake::Extension::SupportedVersions, extensions[0].class
    assert_equal "\x03\x04", extensions[0].extension_data
    assert_equal Raiha::TLS::Handshake::Extension::SupportedGroups, extensions[1].class
    assert_equal "\x03\x04", extensions[1].extension_data
    assert_equal Raiha::TLS::Handshake::Extension::SignatureAlgorithms, extensions[2].class
    assert_equal "\x03\x04", extensions[2].extension_data
  end
end
