require "test_helper"
require "raiha/tls/handshake/extension"

class RaihaTLSHandshakeExtensionSupportedVersionsTest < Minitest::Test
  def test_generate_for_tls13
    ext = Raiha::TLS::Handshake::Extension::SupportedVersions.generate_for_tls13
    assert_equal Raiha::TLS::Handshake::Extension::SupportedVersions, ext.class
    assert_equal_bin "\x02\x03\x04", ext.extension_data
    assert_equal ["\x03\x04"], ext.protocol_versions
  end

  def test_serialize_for_client_hello
    ext = Raiha::TLS::Handshake::Extension::SupportedVersions.new(on: :client_hello)
    ext.protocol_versions = ["\x03\x04"]
    assert_equal_bin "\x00\x2b\x00\x03\x02\x03\x04", ext.serialize
  end

  def test_serialize_for_server_hello
    ext = Raiha::TLS::Handshake::Extension::SupportedVersions.new(on: :server_hello)
    ext.protocol_versions = ["\x03\x04"]
    assert_equal_bin "\x00\x2b\x03\x04", ext.serialize
  end
end
