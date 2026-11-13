# Test helper for the next release of raiha (`Raiha::Next`).

if ENV["COVERAGE"]
  require "simplecov"
  SimpleCov.start do
    add_filter "/test/"
    enable_coverage :branch
  end
end

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
# The next release of raiha is built on Ractors, and Ruby warns that their
# API is experimental the first time one starts.
Warning[:experimental] = false
require "debug"
require "openssl"

require "support/custom_assertion"
require "minitest/autorun"

module NextTestCertificate
  # A self-signed certificate and its key, both in DER, shaped to be passed
  # as `Raiha::Next::TLS::Keyring::Identity.new(**generate_self_signed_certificate)`.
  private def generate_self_signed_certificate(common_name: "localhost")
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.new([["CN", common_name]])
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 86400
    cert.sign(key, "SHA256")

    { cert_der: [cert.to_der], key_der: key.private_to_der }
  end
end
