require "openssl"

module TestCertificate
  private def create_server_config
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.new([["CN", "localhost"]])
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 86400
    cert.sign(key, "SHA256")

    config = Raiha::TLS::Config.server_default
    config.server_certificate = cert
    config.server_private_key = key
    config
  end
end
