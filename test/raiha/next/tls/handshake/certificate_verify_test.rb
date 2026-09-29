require "raiha/next/test_helper"
require "raiha/next/tls/test"

class RaihaNextTLSHandshakeCertificateVerifyTest < Minitest::Test
  TLS = Raiha::Next::TLS
  RFC8448 = TLS::Test::RFC8448::Simple1RTT
  REGISTRY = TLS::Extension::Registry::BUILTIN

  def test_parse_and_encode_rfc8448
    cv = TLS::Handshake.parse(RFC8448::CERTIFICATE_VERIFY, registry: REGISTRY)
    assert_instance_of TLS::Handshake::CertificateVerify, cv
    assert_equal 15, cv.msg_type
    assert_equal 0x0804, cv.algorithm
    assert_equal 128, cv.signature.bytesize
    assert_equal_bin RFC8448::CERTIFICATE_VERIFY, cv.encode
    assert Ractor.shareable?(cv)
  end

  def test_signature_shorter_than_its_length
    assert_raises(TLS::Codec::Truncated) { TLS::Handshake.parse("\x0f\x00\x00\x05\x08\x04\x00\x02\x00".b, registry: REGISTRY) }
  end
end
