require "test_helper"
require "raiha/tls"

class RaihaTLSExtensionSignatureAlgorithmsTest < Minitest::Test
  Codec = Raiha::TLS::Codec
  Extension = Raiha::TLS::Extension

  # signature_algorithms from the RFC 8448 section 3 ClientHello.
  RFC8448_CH = [
    "001e 0403 0503 0603 0203 0804 0805 0806 0401 0501 0601 0201 0402 0502 0602 0202".delete(" ")
  ].pack("H*")

  def test_parse
    ext = Extension::SignatureAlgorithms.parse(RFC8448_CH)
    assert_equal 15, ext.supported_signature_algorithms.size
    assert_equal 0x0403, ext.supported_signature_algorithms.first
    assert_equal 13, ext.extension_type
    assert Ractor.shareable?(ext)
  end

  def test_encode
    assert_equal_bin RFC8448_CH, Extension::SignatureAlgorithms.parse(RFC8448_CH).encode
  end

  def test_bounds
    assert_raises(Codec::RangeViolation) { Extension::SignatureAlgorithms.parse("\x00\x00".b) }
    assert_raises(Codec::RangeViolation) { Extension::SignatureAlgorithms.parse("\xff\xff".b + "\x00".b * 0xffff) }
    assert_raises(Codec::EncodeError) { Extension::SignatureAlgorithms.new(supported_signature_algorithms: []).encode }
  end

  def test_signature_algorithms_cert_shares_the_list
    ext = Extension::SignatureAlgorithmsCert.parse(RFC8448_CH)
    assert_equal Extension::SignatureAlgorithms.parse(RFC8448_CH).supported_signature_algorithms,
      ext.supported_signature_algorithms
    assert_equal 50, ext.extension_type
    assert_equal_bin RFC8448_CH, ext.encode
    refute_equal Extension::SignatureAlgorithms.parse(RFC8448_CH), ext
  end
end
