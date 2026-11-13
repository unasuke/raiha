require "test_helper"
require "raiha/tls"

class RaihaNextTLSSignatureSchemeTest < Minitest::Test
  SignatureScheme = Raiha::Next::TLS::SignatureScheme

  def test_rfc9846_schemes
    assert_equal [
      0x0201, 0x0203, 0x0401, 0x0403, 0x0501, 0x0503, 0x0601, 0x0603,
      0x0804, 0x0805, 0x0806, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b
    ], SignatureScheme::SCHEMES.keys.sort
  end

  def test_descriptor
    scheme = SignatureScheme.find(0x0403)
    assert_equal [:ecdsa_secp256r1_sha256, :ecdsa, :sha256, :secp256r1],
      [scheme.name, scheme.family, scheme.hash_algorithm, scheme.curve]
    ed25519 = SignatureScheme.find(0x0807)
    assert_equal [:eddsa, nil, :ed25519], [ed25519.family, ed25519.hash_algorithm, ed25519.curve]
  end

  # RSASSA-PKCS1-v1_5 and SHA-1 sign certificates only.
  def test_usable_in_certificate_verify
    unusable = SignatureScheme::SCHEMES.values.reject(&:usable_in_certificate_verify?).map(&:name)
    assert_equal %i[rsa_pkcs1_sha1 ecdsa_sha1 rsa_pkcs1_sha256 rsa_pkcs1_sha384 rsa_pkcs1_sha512].sort, unusable.sort
  end

  def test_undefined_code_points
    assert_nil SignatureScheme.find(0x0202)
    assert_nil SignatureScheme.find(0x0a0a)
  end

  def test_shareable
    assert Ractor.shareable?(SignatureScheme::SCHEMES)
  end
end
