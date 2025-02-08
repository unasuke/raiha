require "test_helper"
require "raiha/tls/handshake"

class RaihaTLSHandshakeEncryptedExtensionsTest < Minitest::Test
  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_SERVER_HANDSHAKE_ENCRYPTED_EXTENSIONS = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    08 00 00 24 00 22 00 0a 00 14 00
    12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c
    00 02 40 01 00 00 00 00
  HEX

  def test_deserialize_rfc8448
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_1RTT_SERVER_HANDSHAKE_ENCRYPTED_EXTENSIONS)
    assert_equal Raiha::TLS::Handshake::EncryptedExtensions, handshake.message.class
    assert_equal 3, handshake.message.extensions.length
    assert_equal Raiha::TLS::Handshake::Extension::SupportedGroups, handshake.message.extensions[0].class
    assert_equal Raiha::TLS::Handshake::Extension::RecordSizeLimit, handshake.message.extensions[1].class
    assert_equal Raiha::TLS::Handshake::Extension::ServerName, handshake.message.extensions[2].class
  end
end
