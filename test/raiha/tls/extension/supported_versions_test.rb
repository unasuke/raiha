require "test_helper"
require "raiha/tls"

class RaihaTLSExtensionSupportedVersionsTest < Minitest::Test
  Codec = Raiha::TLS::Codec
  SupportedVersions = Raiha::TLS::Extension::SupportedVersions

  def test_client_hello
    ext = SupportedVersions::CH.parse("\x02\x03\x04".b)
    assert_equal [0x0304], ext.versions
    assert_equal 43, ext.extension_type
    assert_equal_bin "\x02\x03\x04".b, ext.encode
    assert Ractor.shareable?(ext)
  end

  def test_client_hello_bounds
    assert_raises(Codec::RangeViolation) { SupportedVersions::CH.parse("\x00".b) }
    assert_raises(Codec::RangeViolation) { SupportedVersions::CH.parse("\xff".b + "\x03\x04".b * 127 + "\x03".b) }
    assert_raises(Codec::EncodeError) { SupportedVersions::CH.new(versions: []).encode }
  end

  def test_server_hello
    ext = SupportedVersions::SH.parse("\x03\x04".b)
    assert_equal 0x0304, ext.selected_version
    assert_equal 43, ext.extension_type
    assert_equal_bin "\x03\x04".b, ext.encode
    assert_raises(Codec::TrailingData) { SupportedVersions::SH.parse("\x03\x04\x00".b) }
  end
end
