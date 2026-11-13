require "test_helper"
require "raiha/tls/test"

class RaihaTLSHandshakeEncryptedExtensionsTest < Minitest::Test
  TLS = Raiha::TLS
  Extension = TLS::Extension
  RFC8448 = TLS::Test::RFC8448::Simple1RTT
  REGISTRY = Extension::Registry::BUILTIN

  def test_parse_and_encode_rfc8448
    ee = TLS::Handshake.parse(RFC8448::ENCRYPTED_EXTENSIONS, registry: REGISTRY)
    assert_instance_of TLS::Handshake::EncryptedExtensions, ee
    assert_equal 8, ee.msg_type
    assert_equal [10, 28, 0], ee.extensions.map(&:extension_type)
    assert_equal Extension::ServerName::EE.new, ee.extension(0)
    assert_equal_bin RFC8448::ENCRYPTED_EXTENSIONS, ee.encode
    assert Ractor.shareable?(ee)
  end

  def test_may_be_empty
    ee = TLS::Handshake::EncryptedExtensions.new(extensions: [])
    assert_equal_bin "\x08\x00\x00\x02\x00\x00".b, ee.encode
    assert_equal ee, TLS::Handshake.parse(ee.encode, registry: REGISTRY)
  end

  def test_rejects_an_extension_not_allowed_there
    ee = TLS::Handshake::EncryptedExtensions.new(extensions: [Extension::KeyShare::HRR.new(selected_group: 0x001d)])
    assert_raises(TLS::Codec::IllegalPlacement) { TLS::Handshake.parse(ee.encode, registry: REGISTRY) }
  end
end
