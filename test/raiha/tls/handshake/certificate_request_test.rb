require "test_helper"
require "raiha/tls"

class RaihaNextTLSHandshakeCertificateRequestTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Extension = TLS::Extension
  REGISTRY = Extension::Registry::BUILTIN

  def test_round_trip
    cr = TLS::Handshake::CertificateRequest.new(
      certificate_request_context: "".b,
      extensions: [
        Extension::SignatureAlgorithms.new(supported_signature_algorithms: [0x0403, 0x0804]),
        Extension::Opaque.new(type: 5, data: "\x01\x00\x00\x00\x00".b)
      ]
    )
    bytes = cr.encode
    assert_equal 13, bytes.getbyte(0)
    parsed = TLS::Handshake.parse(bytes, registry: REGISTRY)
    assert_equal cr, parsed
    assert_equal [0x0403, 0x0804], parsed.extension(13).supported_signature_algorithms
    assert Ractor.shareable?(parsed)
  end

  def test_rejects_an_extension_not_allowed_there
    cr = TLS::Handshake::CertificateRequest.new(certificate_request_context: "".b,
      extensions: [Extension::Alpn.new(protocol_name_list: ["h3"])])
    assert_raises(TLS::Codec::IllegalPlacement) { TLS::Handshake.parse(cr.encode, registry: REGISTRY) }
  end
end
