require "test_helper"
require "support/rfc8448_test_vector"
require "openssl"
require "raiha/tls/handshake"

class RaihaTLSHandshakeCertificateTest < Minitest::Test
  def test_deserialize_rfc8448
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE)
    assert_equal Raiha::TLS::Handshake::Certificate, handshake.message.class
    assert_equal "", handshake.message.certificate_request_context
    assert_equal 1, handshake.message.certificate_entries.length
    assert_equal 0, handshake.message.certificate_entries.first.extensions.length
    assert_equal OpenSSL::X509::Certificate, OpenSSL::X509::Certificate.new(handshake.message.certificates.first).class
  end

  def test_serialize_rfc8448
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE)
    assert_equal_bin RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE, handshake.serialize
  end

  def test_serialize_and_deserialize
    cert = generate_temporary_rsa_certificate
    handshake = Raiha::TLS::Handshake.new.tap do |hs|
      hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:certificate]
      hs.message = Raiha::TLS::Handshake::Certificate.new.tap do |cv|
        cv.certificate_entries << Raiha::TLS::Handshake::Certificate::CertificateEntry.new(
          opaque_certificate_data: cert.to_der,
          extensions: []
        )
      end
    end

    serialized = handshake.serialize
    deserialized = Raiha::TLS::Handshake.deserialize(serialized)
    assert_equal Raiha::TLS::Handshake::Certificate, deserialized.message.class
    assert_equal cert.to_der, deserialized.message.certificate_entries.first.opaque_certificate_data
    assert_equal_bin deserialized.serialize, serialized
  end

  def generate_temporary_rsa_certificate
    rsa = OpenSSL::PKey::RSA.generate(2048)
    csr = OpenSSL::X509::Request.new
    name = OpenSSL::X509::Name.new
    name.add_entry("CN", "localhost")
    name.add_entry("DC", "localhost")
    csr.subject = name
    csr.version = 0
    csr.public_key = rsa.public_key
    factory = OpenSSL::X509::ExtensionFactory.new
    exts = [factory.create_ext("subjectAltName", "DNS:localhost")]
    asn1exts = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence(exts)])
    csr.add_attribute(OpenSSL::X509::Attribute.new("extReq", asn1exts))
    csr.sign(rsa, "sha256")
    cert = OpenSSL::X509::Certificate.new
    cert.serial = 0
    cert.version = 2
    cert.not_before = Time.now
    cert.not_after = Time.now + 60 # 1 minutes
    cert.subject = name
    cert.issuer = name
    cert.public_key = csr.public_key
    cert.sign(rsa, "sha256")
    cert
  end
end
