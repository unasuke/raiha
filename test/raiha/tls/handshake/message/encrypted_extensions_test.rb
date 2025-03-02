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

  def test_serialize_and_deserialize
    handshake = Raiha::TLS::Handshake.new.tap do |hs|
      hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:encrypted_extensions]
      hs.message = Raiha::TLS::Handshake::EncryptedExtensions.new.tap do |ee|
        ee.extensions = [
          Raiha::TLS::Handshake::Extension::SupportedGroups.new(on: :encrypted_extensions).tap do |sg|
            sg.groups = ["prime256v1", "x25519"]
          end
        ]
      end
    end

    serialized = handshake.serialize
    deserialized = Raiha::TLS::Handshake.deserialize(serialized)
    assert_equal Raiha::TLS::Handshake::EncryptedExtensions, deserialized.message.class
    assert_equal Raiha::TLS::Handshake::Extension::SupportedGroups, deserialized.message.extensions[0].class
    assert_equal ["prime256v1", "x25519"], deserialized.message.extensions[0].groups
    assert_equal_bin deserialized.serialize, serialized
  end
end
