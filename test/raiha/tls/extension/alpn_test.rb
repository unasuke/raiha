require "test_helper"
require "raiha/tls"

class RaihaNextTLSExtensionAlpnTest < Minitest::Test
  Codec = Raiha::TLS::Codec
  Alpn = Raiha::TLS::Extension::Alpn

  def test_parse_and_encode
    data = "\x00\x0c\x02h3\x08http/1.1".b
    ext = Alpn.parse(data)
    assert_equal ["h3", "http/1.1"], ext.protocol_name_list
    assert_equal 16, ext.extension_type
    assert_equal_bin data, ext.encode
    assert Ractor.shareable?(ext)
  end

  def test_empty_protocol_name
    assert_raises(Codec::RangeViolation) { Alpn.parse("\x00\x02\x00\x00".b) }
    assert_raises(Codec::EncodeError) { Alpn.new(protocol_name_list: [""]).encode }
  end

  def test_empty_list
    assert_raises(Codec::RangeViolation) { Alpn.parse("\x00\x00".b) }
    assert_raises(Codec::EncodeError) { Alpn.new(protocol_name_list: []).encode }
  end
end
