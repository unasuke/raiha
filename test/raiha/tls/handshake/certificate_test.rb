require "test_helper"
require "raiha/tls/test"

class RaihaTLSHandshakeCertificateTest < Minitest::Test
  TLS = Raiha::TLS
  Extension = TLS::Extension
  RFC8448 = TLS::Test::RFC8448::Simple1RTT
  REGISTRY = Extension::Registry::BUILTIN

  def test_parse_and_encode_rfc8448
    cert = TLS::Handshake.parse(RFC8448::CERTIFICATE, registry: REGISTRY)
    assert_instance_of TLS::Handshake::Certificate, cert
    assert_equal 11, cert.msg_type
    assert_equal "".b, cert.certificate_request_context
    assert_equal 1, cert.certificate_list.size
    entry = cert.certificate_list.first
    assert_equal "rsa", OpenSSL::X509::Certificate.new(entry.cert_data).subject.to_a.dig(0, 1)
    assert_empty entry.extensions
    assert_equal_bin RFC8448::CERTIFICATE, cert.encode
    assert Ractor.shareable?(cert)
  end

  def test_entry_extensions_have_a_context_of_their_own
    status = Extension::Opaque.new(type: 5, data: "\x01\x00\x00\x01\x00".b)
    sct = Extension::Opaque.new(type: 18, data: "\x00\x00".b)
    cert = TLS::Handshake::Certificate.new(certificate_request_context: "".b,
      certificate_list: [TLS::Handshake::CertificateEntry.new(cert_data: "der".b, extensions: [status, sct])])
    parsed = TLS::Handshake.parse(cert.encode, registry: REGISTRY)
    assert_equal status, parsed.certificate_list.first.extension(5)
    assert_equal cert, parsed

    bad = cert.with(certificate_list: [TLS::Handshake::CertificateEntry.new(cert_data: "der".b,
      extensions: [Extension::SupportedVersions::SH.new(selected_version: 0x0304)])])
    assert_raises(TLS::Codec::IllegalPlacement) { TLS::Handshake.parse(bad.encode, registry: REGISTRY) }
  end

  def test_empty_list_parses
    cert = TLS::Handshake::Certificate.new(certificate_request_context: "".b, certificate_list: [])
    assert_equal cert, TLS::Handshake.parse(cert.encode, registry: REGISTRY)
  end

  def test_empty_cert_data
    assert_raises(TLS::Codec::RangeViolation) do
      TLS::Handshake.parse("\x0b\x00\x00\x09\x00\x00\x00\x05\x00\x00\x00\x00\x00".b, registry: REGISTRY)
    end
    entry = TLS::Handshake::CertificateEntry.new(cert_data: "".b, extensions: [])
    cert = TLS::Handshake::Certificate.new(certificate_request_context: "".b, certificate_list: [entry])
    assert_raises(TLS::Codec::EncodeError) { cert.encode }
  end
end
