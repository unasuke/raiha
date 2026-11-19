require "test_helper"
require "raiha/tls"

class RaihaTLSCryptoCertificateTest < Minitest::Test
  Certificate = Raiha::TLS::Crypto::Certificate

  def signed(key, digest)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = cert.issuer = OpenSSL::X509::Name.new([["CN", "signed"]])
    cert.public_key = key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 60
    cert.sign(key, digest)
    cert
  end

  # The code point of a certificate's own signature, whatever the library
  # calls its algorithm: LibreSSL names Ed25519 "Ed25519", OpenSSL "ED25519".
  def test_signature_scheme_id
    assert_equal 0x0403, Certificate.signature_scheme_id(signed(OpenSSL::PKey::EC.generate("prime256v1"), "SHA256"))
    assert_equal 0x0503, Certificate.signature_scheme_id(signed(OpenSSL::PKey::EC.generate("secp384r1"), "SHA384"))
    assert_equal 0x0401, Certificate.signature_scheme_id(signed(OpenSSL::PKey::RSA.generate(2048), "SHA256"))
    assert_equal 0x0807, Certificate.signature_scheme_id(signed(OpenSSL::PKey.generate_key("ED25519"), nil))
  end
end
