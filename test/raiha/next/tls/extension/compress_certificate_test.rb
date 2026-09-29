require "raiha/next/test_helper"
require "raiha/next/tls"

class RaihaNextTLSExtensionCompressCertificateTest < Minitest::Test
  Codec = Raiha::Next::TLS::Codec
  CompressCertificate = Raiha::Next::TLS::Extension::CompressCertificate

  def test_parse_and_encode
    ext = CompressCertificate.parse("\x04\x00\x01\x00\x02".b)
    assert_equal [1, 2], ext.algorithms
    assert_equal 27, ext.extension_type
    assert_equal_bin "\x04\x00\x01\x00\x02".b, ext.encode
  end

  def test_bounds
    assert_raises(Codec::RangeViolation) { CompressCertificate.parse("\x00".b) }
    assert_raises(Codec::RangeViolation) { CompressCertificate.parse("\xff".b + "\x00".b * 0xff) }
    assert_raises(Codec::EncodeError) { CompressCertificate.new(algorithms: []).encode }
    assert_raises(Codec::EncodeError) { CompressCertificate.new(algorithms: [1] * 128).encode }
  end
end
