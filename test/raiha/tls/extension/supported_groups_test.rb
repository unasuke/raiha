require "test_helper"
require "raiha/tls"

class RaihaTLSExtensionSupportedGroupsTest < Minitest::Test
  Codec = Raiha::TLS::Codec
  SupportedGroups = Raiha::TLS::Extension::SupportedGroups

  # supported_groups from the RFC 8448 section 3 ClientHello.
  RFC8448_CH = ["001200 1d00 1700 1800 1901 0001 0101 0201 0301 04".delete(" ")].pack("H*")

  def test_parse
    ext = SupportedGroups.parse(RFC8448_CH)
    assert_equal [0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104], ext.named_group_list
    assert_equal 10, ext.extension_type
    assert Ractor.shareable?(ext)
  end

  def test_encode
    assert_equal_bin RFC8448_CH, SupportedGroups.parse(RFC8448_CH).encode
  end

  def test_bounds
    assert_raises(Codec::RangeViolation) { SupportedGroups.parse("\x00\x00".b) }
    assert_raises(Codec::EncodeError) { SupportedGroups.new(named_group_list: []).encode }
  end

  def test_odd_length
    assert_raises(Codec::Truncated) { SupportedGroups.parse("\x00\x03\x00\x1d\x00".b) }
  end

  def test_trailing_data
    assert_raises(Codec::TrailingData) { SupportedGroups.parse("\x00\x02\x00\x1d\x00".b) }
  end
end
