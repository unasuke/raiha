require "test_helper"
require "support/rfc8448_test_vector"
require "raiha/tls/handshake"

class RaihaTLSHandshakeEncryptedExtensionsTest < Minitest::Test
  def test_deserialize_rfc8448
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_ENCRYPTED_EXTENSIONS)
    assert_equal Raiha::TLS::Handshake::EncryptedExtensions, handshake.message.class
    assert_equal 3, handshake.message.extensions.length
    assert_equal Raiha::TLS::Handshake::Extension::SupportedGroups, handshake.message.extensions[0].class
    assert_equal Raiha::TLS::Handshake::Extension::RecordSizeLimit, handshake.message.extensions[1].class
    assert_equal Raiha::TLS::Handshake::Extension::ServerName, handshake.message.extensions[2].class
  end

  def test_serialize_rfc8448
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_ENCRYPTED_EXTENSIONS)
    serialized = handshake.serialize
    assert_equal_bin RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_ENCRYPTED_EXTENSIONS, serialized
  end
end
