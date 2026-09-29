require "raiha/next/test_helper"
require "raiha/next/tls"

class RaihaNextTLSExtensionRecordSizeLimitTest < Minitest::Test
  Codec = Raiha::Next::TLS::Codec
  RecordSizeLimit = Raiha::Next::TLS::Extension::RecordSizeLimit

  # record_size_limit from the RFC 8448 section 3 ClientHello.
  def test_parse_and_encode
    ext = RecordSizeLimit.parse("\x40\x01".b)
    assert_equal 0x4001, ext.record_size_limit
    assert_equal 28, ext.extension_type
    assert_equal_bin "\x40\x01".b, ext.encode
  end

  def test_wrong_length
    assert_raises(Codec::Truncated) { RecordSizeLimit.parse("\x40".b) }
    assert_raises(Codec::TrailingData) { RecordSizeLimit.parse("\x40\x01\x00".b) }
  end
end
