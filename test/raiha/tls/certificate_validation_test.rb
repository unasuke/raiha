require "test_helper"
require "openssl"
require_relative "../../../lib/raiha/tls/handshake"
require_relative "../../../lib/raiha/tls/trust_store"

class RaihaTLSCertificateValidationTest < Minitest::Test
  def test_valid_self_signed_certificate
    ca_key, ca_cert = generate_ca
    store = Raiha::TLS::TrustStore.new
    store.add_cert(ca_cert)

    _leaf_key, leaf_cert = generate_leaf(ca_key, ca_cert, "example.com")
    certificate = build_certificate_message([leaf_cert])

    assert certificate.valid?(hostname: "example.com", trust_store: store)
  end

  def test_valid_certificate_chain
    ca_key, ca_cert = generate_ca
    store = Raiha::TLS::TrustStore.new
    store.add_cert(ca_cert)

    intermediate_key, intermediate_cert = generate_intermediate(ca_key, ca_cert)
    _leaf_key, leaf_cert = generate_leaf(intermediate_key, intermediate_cert, "example.com")
    certificate = build_certificate_message([leaf_cert, intermediate_cert])

    assert certificate.valid?(hostname: "example.com", trust_store: store)
  end

  def test_expired_certificate
    ca_key, ca_cert = generate_ca
    store = Raiha::TLS::TrustStore.new
    store.add_cert(ca_cert)

    leaf_key = OpenSSL::PKey::EC.generate("prime256v1")
    leaf_cert = OpenSSL::X509::Certificate.new
    leaf_cert.version = 2
    leaf_cert.serial = 2
    leaf_cert.subject = OpenSSL::X509::Name.new([["CN", "expired.example.com"]])
    leaf_cert.issuer = ca_cert.subject
    leaf_cert.public_key = leaf_key
    leaf_cert.not_before = Time.now - 7200
    leaf_cert.not_after = Time.now - 3600
    add_san(leaf_cert, ca_cert, "expired.example.com")
    leaf_cert.sign(ca_key, "SHA256")

    certificate = build_certificate_message([leaf_cert])
    refute certificate.valid?(hostname: "expired.example.com", trust_store: store)
  end

  def test_hostname_mismatch
    ca_key, ca_cert = generate_ca
    store = Raiha::TLS::TrustStore.new
    store.add_cert(ca_cert)

    _leaf_key, leaf_cert = generate_leaf(ca_key, ca_cert, "example.com")
    certificate = build_certificate_message([leaf_cert])

    refute certificate.valid?(hostname: "other.com", trust_store: store)
  end

  def test_wildcard_certificate
    ca_key, ca_cert = generate_ca
    store = Raiha::TLS::TrustStore.new
    store.add_cert(ca_cert)

    _leaf_key, leaf_cert = generate_leaf(ca_key, ca_cert, "*.example.com")
    certificate = build_certificate_message([leaf_cert])

    assert certificate.valid?(hostname: "www.example.com", trust_store: store)
    refute certificate.valid?(hostname: "example.com", trust_store: store)
    refute certificate.valid?(hostname: "sub.www.example.com", trust_store: store)
  end

  def test_untrusted_certificate
    store = Raiha::TLS::TrustStore.new

    other_key, other_cert = generate_ca
    _leaf_key, leaf_cert = generate_leaf(other_key, other_cert, "example.com")
    certificate = build_certificate_message([leaf_cert])

    refute certificate.valid?(hostname: "example.com", trust_store: store)
  end

  def test_empty_certificate
    certificate = Raiha::TLS::Handshake::Certificate.new
    refute certificate.valid?
  end

  def test_valid_without_hostname_check
    ca_key, ca_cert = generate_ca
    store = Raiha::TLS::TrustStore.new
    store.add_cert(ca_cert)

    _leaf_key, leaf_cert = generate_leaf(ca_key, ca_cert, "example.com")
    certificate = build_certificate_message([leaf_cert])

    assert certificate.valid?(trust_store: store)
  end

  private def generate_ca
    key = OpenSSL::PKey::EC.generate("prime256v1")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.new([["CN", "Test CA"]])
    cert.issuer = cert.subject
    cert.public_key = key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 86400

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
    cert.add_extension(ef.create_extension("keyUsage", "keyCertSign,cRLSign", true))
    cert.add_extension(ef.create_extension("subjectKeyIdentifier", "hash"))

    cert.sign(key, "SHA256")
    [key, cert]
  end

  private def generate_intermediate(ca_key, ca_cert)
    key = OpenSSL::PKey::EC.generate("prime256v1")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 10
    cert.subject = OpenSSL::X509::Name.new([["CN", "Test Intermediate CA"]])
    cert.issuer = ca_cert.subject
    cert.public_key = key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 86400

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = ca_cert
    cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
    cert.add_extension(ef.create_extension("keyUsage", "keyCertSign,cRLSign", true))
    cert.add_extension(ef.create_extension("subjectKeyIdentifier", "hash"))
    cert.add_extension(ef.create_extension("authorityKeyIdentifier", "keyid:always"))

    cert.sign(ca_key, "SHA256")
    [key, cert]
  end

  private def generate_leaf(issuer_key, issuer_cert, hostname)
    key = OpenSSL::PKey::EC.generate("prime256v1")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 2
    cert.subject = OpenSSL::X509::Name.new([["CN", hostname]])
    cert.issuer = issuer_cert.subject
    cert.public_key = key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 86400
    add_san(cert, issuer_cert, hostname)
    cert.sign(issuer_key, "SHA256")
    [key, cert]
  end

  private def add_san(cert, issuer_cert, hostname)
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = issuer_cert
    cert.add_extension(ef.create_extension("subjectAltName", "DNS:#{hostname}"))
  end

  private def build_certificate_message(certs)
    Raiha::TLS::Handshake::Certificate.new.tap do |msg|
      certs.each do |cert|
        msg.certificate_entries << Raiha::TLS::Handshake::Certificate::CertificateEntry.new(
          opaque_certificate_data: cert.to_der,
          extensions: []
        )
      end
    end
  end
end
