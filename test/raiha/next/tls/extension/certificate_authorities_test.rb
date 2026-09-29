require "raiha/next/test_helper"
require "raiha/next/tls"

class RaihaNextTLSExtensionCertificateAuthoritiesTest < Minitest::Test
  Codec = Raiha::Next::TLS::Codec
  CertificateAuthorities = Raiha::Next::TLS::Extension::CertificateAuthorities

  def test_parse_and_encode
    data = "\x00\x0a\x00\x03abc\x00\x03def".b
    ext = CertificateAuthorities.parse(data)
    assert_equal ["abc".b, "def".b], ext.authorities
    assert_equal 47, ext.extension_type
    assert_equal_bin data, ext.encode
    assert Ractor.shareable?(ext)
  end

  def test_bounds
    assert_raises(Codec::RangeViolation) { CertificateAuthorities.parse("\x00\x02\x00\x00".b) }
    assert_raises(Codec::RangeViolation) { CertificateAuthorities.parse("\x00\x03\x00\x00\x00".b) }
    assert_raises(Codec::EncodeError) { CertificateAuthorities.new(authorities: []).encode }
  end
end
