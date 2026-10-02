require "raiha/next/test_helper"
require "raiha/next/tls"

class RaihaNextTLSCryptoDigestTest < Minitest::Test
  Crypto = Raiha::Next::TLS::Crypto

  def test_digest_keeps_accumulating
    d = Crypto::Digest.new(:sha256)
    d << "ab"
    assert_equal_bin OpenSSL::Digest.digest("SHA256", "ab"), d.digest
    d << "c"
    assert_equal_bin OpenSSL::Digest.digest("SHA256", "abc"), d.digest
    assert_equal :sha256, d.hash_name
  end

  def test_dup_is_independent
    d = Crypto::Digest.new(:sha384)
    d << "ab"
    copy = d.dup
    copy << "c"
    assert_equal_bin OpenSSL::Digest.digest("SHA384", "ab"), d.digest
    assert_equal_bin OpenSSL::Digest.digest("SHA384", "abc"), copy.digest
  end

  def test_hash_lengths
    assert_equal 32, Crypto.hash_length(:sha256)
    assert_equal 48, Crypto.hash_length(:sha384)
    assert_equal 48, Crypto.hash(:sha384, "").bytesize
    assert_raises(ArgumentError) { Crypto::Digest.new(:sha1) }
  end

  def test_fixed_length_secure_compare
    assert Crypto.fixed_length_secure_compare("abc".b, "abc".b)
    refute Crypto.fixed_length_secure_compare("abc".b, "abd".b)
  end

  # A length mismatch is a bug in the caller, which must check the length
  # first; answering false would hide that.
  def test_fixed_length_secure_compare_rejects_different_lengths
    assert_raises(ArgumentError) { Crypto.fixed_length_secure_compare("abc".b, "ab".b) }
  end
end
