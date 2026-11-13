require "openssl"

# A CA and a server certificate it issues for "localhost", made each time an
# example runs, so that its client trusts the CA alone.
module ExampleCertificate
  class << self
    # The CA's certificate, DER-encoded, as a client's trust anchor.
    def ca_der = ca.first.to_der

    # The server's certificate chain and key, as a Keyring takes them.
    def identity
      @identity ||= begin
        ca_cert, ca_key = ca
        key = OpenSSL::PKey::EC.generate("prime256v1")
        cert = certificate("localhost", key, issuer: ca_cert) do |factory|
          [factory.create_extension("basicConstraints", "CA:FALSE", true),
            factory.create_extension("extendedKeyUsage", "serverAuth"),
            factory.create_extension("subjectAltName", "DNS:localhost")]
        end
        cert.sign(ca_key, "SHA256")
        Raiha::Next::TLS::Keyring::Identity.new(cert_der: [cert.to_der, ca_cert.to_der], key_der: key.private_to_der)
      end
    end

    private def ca
      @ca ||= begin
        key = OpenSSL::PKey::EC.generate("prime256v1")
        cert = certificate("Example CA", key) do |factory|
          [factory.create_extension("basicConstraints", "CA:TRUE", true),
            factory.create_extension("keyUsage", "keyCertSign,cRLSign", true)]
        end
        cert.sign(key, "SHA256")
        [cert, key]
      end
    end

    # A certificate of `key` for `name`, issued by `issuer` or by itself,
    # with the extensions the block makes.
    private def certificate(name, key, issuer: nil)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = issuer ? 2 : 1
      cert.subject = OpenSSL::X509::Name.new([["CN", name]])
      cert.issuer = issuer ? issuer.subject : cert.subject
      cert.public_key = key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = cert
      factory.issuer_certificate = issuer || cert
      yield(factory).each { |extension| cert.add_extension(extension) }
      cert
    end
  end
end
