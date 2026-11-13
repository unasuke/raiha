require "openssl"

# Certificates for tests of the next release of raiha: a CA and the leaves it
# issues, with the names and validity a test asks for. Keys are generated
# once per process and reused, since RSA generation is slow.
module NextTestPKI
  # The time the certificates are valid around: when the tests run, so that
  # a peer checking them against its own clock accepts them too. Tests pass
  # it as `now:`. Whole seconds, as a certificate keeps no finer time.
  NOW = Time.at(Time.now.to_i).utc

  Issued = Data.define(:certificate, :key) do
    def der = certificate.to_der
    def key_der = key.private_to_der
  end

  module_function

  # A key of the kind named; any other name is a P-256 key of its own, such
  # as :ca.
  def key(kind = :p256)
    @keys ||= {}
    @keys[kind] ||= case kind
      when :p384 then OpenSSL::PKey::EC.generate("secp384r1")
      when :rsa then OpenSSL::PKey::RSA.generate(2048)
      when :ed25519 then OpenSSL::PKey.generate_key("ED25519")
      else OpenSSL::PKey::EC.generate("prime256v1")
      end
  end

  def ca(name: "Next Test CA", key: key(:ca), not_before: NOW - 86400, not_after: NOW + 86400 * 365)
    issue(subject: name, key:, issuer: nil, not_before:, not_after:, ca: true)
  end

  # A leaf for `names`: "DNS:..." and "IP:..." entries of subjectAltName,
  # or none at all when `names` is empty.
  def leaf(issuer, names: ["DNS:localhost"], common_name: "leaf", key: key(:p256), purpose: "serverAuth",
    not_before: NOW - 86400, not_after: NOW + 86400 * 30, serial: 2)
    issue(subject: common_name, key:, issuer:, not_before:, not_after:, ca: false, names:, purpose:, serial:)
  end

  def issue(subject:, key:, issuer:, not_before:, not_after:, ca:, names: [], purpose: nil, serial: 1)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = OpenSSL::X509::Name.new([["CN", subject]])
    cert.issuer = issuer ? issuer.certificate.subject : cert.subject
    cert.public_key = key
    cert.not_before = not_before
    cert.not_after = not_after
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer ? issuer.certificate : cert
    if ca
      cert.add_extension(factory.create_extension("basicConstraints", "CA:TRUE", true))
      cert.add_extension(factory.create_extension("keyUsage", "keyCertSign,cRLSign", true))
    else
      cert.add_extension(factory.create_extension("basicConstraints", "CA:FALSE", true))
      cert.add_extension(factory.create_extension("extendedKeyUsage", purpose)) if purpose
      cert.add_extension(factory.create_extension("subjectAltName", names.join(","))) unless names.empty?
    end
    signer = issuer ? issuer.key : key
    cert.sign(signer, signer.oid == "ED25519" ? nil : "SHA256")
    Issued.new(certificate: cert, key:)
  end
end
