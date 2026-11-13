require "test_helper"
require "raiha/tls"

class RaihaTLSCryptoHKDFTest < Minitest::Test
  HKDF = Raiha::TLS::Crypto::HKDF

  def hex(s) = [s.delete(" ")].pack("H*")

  # RFC 5869 appendix A.1: basic test case with SHA-256.
  def test_rfc5869_case1
    prk = HKDF.extract(hash: :sha256, salt: hex("000102030405060708090a0b0c"), ikm: "\x0b".b * 22)
    assert_equal_bin hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), prk
    okm = HKDF.expand(hash: :sha256, prk:, info: hex("f0f1f2f3f4f5f6f7f8f9"), length: 42)
    assert_equal_bin hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), okm
  end

  # RFC 5869 appendix A.3: SHA-256 with an empty salt and info.
  def test_rfc5869_case3
    prk = HKDF.extract(hash: :sha256, salt: "".b, ikm: "\x0b".b * 22)
    assert_equal_bin hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"), prk
    okm = HKDF.expand(hash: :sha256, prk:, info: "".b, length: 42)
    assert_equal_bin hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"), okm
  end

  def test_matches_openssl_one_shot_hkdf
    rng = Random.new(5869)
    [[:sha256, "SHA256", 32], [:sha384, "SHA384", 48]].each do |hash, name, hash_length|
      [1, hash_length, hash_length + 1, 3 * hash_length].each do |length|
        salt = rng.bytes(rng.rand(0..64))
        ikm = rng.bytes(rng.rand(1..64))
        info = rng.bytes(rng.rand(0..32))
        prk = HKDF.extract(hash:, salt:, ikm:)
        expected = OpenSSL::KDF.hkdf(ikm, salt:, info:, length:, hash: name)
        assert_equal_bin expected, HKDF.expand(hash:, prk:, info:, length:)
      end
    end
  end

  def test_expand_to_nothing
    assert_equal "".b, HKDF.expand(hash: :sha256, prk: "k".b * 32, info: "".b, length: 0)
  end

  def test_expand_length_is_bounded
    assert_raises(ArgumentError) { HKDF.expand(hash: :sha256, prk: "k".b * 32, info: "".b, length: 255 * 32 + 1) }
    assert_equal 255 * 32, HKDF.expand(hash: :sha256, prk: "k".b * 32, info: "".b, length: 255 * 32).bytesize
  end

  def test_unknown_hash
    assert_raises(ArgumentError) { HKDF.extract(hash: :md5, salt: "".b, ikm: "k".b) }
  end
end
