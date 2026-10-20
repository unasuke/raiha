require "raiha/next/test_helper"
require "raiha/next/tls/test"

class RaihaNextTLSCryptoSignatureTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Signature = TLS::Crypto::Signature
  RFC8448 = TLS::Test::RFC8448::Simple1RTT

  def scheme(name) = TLS::Config::SCHEMES_BY_NAME.fetch(name)

  def keys
    @keys ||= {
      rsa: OpenSSL::PKey::RSA.generate(2048),
      p256: OpenSSL::PKey::EC.generate("prime256v1"),
      p384: OpenSSL::PKey::EC.generate("secp384r1"),
      ed25519: OpenSSL::PKey.generate_key("ED25519")
    }
  end

  def test_sign_and_verify
    {
      rsa_pss_rsae_sha256: :rsa, rsa_pss_rsae_sha512: :rsa, ecdsa_secp256r1_sha256: :p256,
      ecdsa_secp384r1_sha384: :p384, ed25519: :ed25519
    }.each do |name, key_name|
      key = keys.fetch(key_name)
      signature = Signature.sign(scheme(name), key, "data")
      assert Signature.verify(scheme(name), key, signature, "data"), name
      refute Signature.verify(scheme(name), key, signature, "Data"), name
    end
  end

  # A peer's signature that is garbage, or of the wrong kind for the key,
  # is false, never an exception.
  def test_verify_never_raises
    refute Signature.verify(scheme(:rsa_pss_rsae_sha256), keys[:rsa], "\x00".b, "data")
    refute Signature.verify(scheme(:ecdsa_secp256r1_sha256), keys[:p256], "garbage".b, "data")
    refute Signature.verify(scheme(:ed25519), keys[:ed25519], "".b, "data")
    p256_signature = Signature.sign(scheme(:ecdsa_secp256r1_sha256), keys[:p256], "data")
    refute Signature.verify(scheme(:ecdsa_secp384r1_sha384), keys[:p256], p256_signature, "data")
    refute Signature.verify(scheme(:rsa_pss_rsae_sha256), keys[:p256], p256_signature, "data")
  end

  # RFC 9846 requires the RSASSA-PSS salt to be as long as the digest.
  def test_rsa_pss_salt_must_match_the_digest
    short_salt = keys[:rsa].sign_pss("SHA256", "data", salt_length: 0, mgf1_hash: "SHA256")
    refute Signature.verify(scheme(:rsa_pss_rsae_sha256), keys[:rsa], short_salt, "data")
  end

  def test_key_matches
    assert Signature.key_matches?(scheme(:rsa_pss_rsae_sha384), keys[:rsa])
    refute Signature.key_matches?(scheme(:rsa_pss_rsae_sha256), keys[:p256])
    assert Signature.key_matches?(scheme(:ecdsa_secp256r1_sha256), keys[:p256])
    refute Signature.key_matches?(scheme(:ecdsa_secp384r1_sha384), keys[:p256])
    assert Signature.key_matches?(scheme(:ed25519), keys[:ed25519])
    refute Signature.key_matches?(scheme(:ed448), keys[:ed25519])
    refute Signature.key_matches?(scheme(:rsa_pss_pss_sha256), keys[:rsa])
  end

  # A private key reads from its DER whatever its kind, Ed25519 among
  # them; a public key or bytes that are no key are nil.
  def test_private_key
    keys.each do |name, key|
      assert_equal key.public_to_der, Signature.private_key(key.private_to_der)&.public_to_der, name
      assert_nil Signature.private_key(key.public_to_der), name
    end
    assert_nil Signature.private_key("garbage".b)
  end

  # The server's CertificateVerify in RFC 8448 verifies against the
  # certificate it sent, over the content RFC 9846 "Certificate Verify"
  # defines.
  def test_rfc8448_certificate_verify
    certificate = TLS::Handshake.parse(RFC8448::CERTIFICATE, registry: TLS::Extension::Registry::BUILTIN)
    leaf = TLS::Crypto::Certificate.parse(certificate.certificate_list.first.cert_data)
    verify = TLS::Handshake.parse(RFC8448::CERTIFICATE_VERIFY, registry: TLS::Extension::Registry::BUILTIN)
    transcript_hash = TLS::Crypto.hash(:sha256,
      RFC8448::CLIENT_HELLO + RFC8448::SERVER_HELLO + RFC8448::ENCRYPTED_EXTENSIONS + RFC8448::CERTIFICATE)
    content = (" " * 64) + "TLS 1.3, server CertificateVerify" + "\x00" + transcript_hash
    assert Signature.verify(TLS::SignatureScheme.find(verify.algorithm), leaf.public_key, verify.signature, content.b)
  end

  def test_certificate_parse
    assert_nil TLS::Crypto::Certificate.parse("garbage".b)
  end
end
