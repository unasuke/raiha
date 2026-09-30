require "raiha/next/test_helper"
require "raiha/next/tls"

class RaihaNextTLSCipherSuiteTest < Minitest::Test
  TLS = Raiha::Next::TLS
  CipherSuite = TLS::CipherSuite

  def test_descriptors
    aes128 = CipherSuite.find(0x1301)
    assert_same CipherSuite::TLS_AES_128_GCM_SHA256, aes128
    assert_equal [:sha256, 32, :aes_128_gcm, 16, 12, 16],
      [aes128.hash_algorithm, aes128.hash_length, aes128.aead, aes128.key_length, aes128.iv_length, aes128.tag_length]
    aes256 = CipherSuite.find(0x1302)
    assert_equal [:sha384, 48, :aes_256_gcm, 32], [aes256.hash_algorithm, aes256.hash_length, aes256.aead, aes256.key_length]
    chacha = CipherSuite.find(0x1303)
    assert_equal [:sha256, :chacha20_poly1305, 32], [chacha.hash_algorithm, chacha.aead, chacha.key_length]
  end

  def test_names_match_iana
    CipherSuite::SUITES.each_value { |suite| assert_equal TLS::IANA.cipher_suite_name(suite.id), suite.name }
  end

  def test_ccm_suites_are_not_supported
    assert_nil CipherSuite.find(0x1304)
    assert_nil CipherSuite.find(0x1305)
  end

  # RFC 9846: AES-GCM up to 2^24.5 full-size records; no integrity limit.
  # RFC 9001: AES-GCM 2^23 packets and 2^52 forgeries.
  def test_aes_gcm_limits
    [CipherSuite::TLS_AES_128_GCM_SHA256, CipherSuite::TLS_AES_256_GCM_SHA384].each do |suite|
      assert_equal (2**24.5).floor, suite.confidentiality_limit(:tcp)
      assert_nil suite.integrity_limit(:tcp)
      assert_equal 2**23, suite.confidentiality_limit(:quic)
      assert_equal 2**52, suite.integrity_limit(:quic)
    end
  end

  # ChaCha20-Poly1305 has no confidentiality limit either way, and RFC 9001
  # limits it to 2^36 forgeries.
  def test_chacha20_limits
    suite = CipherSuite::TLS_CHACHA20_POLY1305_SHA256
    assert_nil suite.confidentiality_limit(:tcp)
    assert_nil suite.integrity_limit(:tcp)
    assert_nil suite.confidentiality_limit(:quic)
    assert_equal 2**36, suite.integrity_limit(:quic)
  end

  def test_unknown_transport
    assert_raises(KeyError) { CipherSuite::TLS_AES_128_GCM_SHA256.confidentiality_limit(:udp) }
  end

  def test_shareable_and_usable_as_hash_keys
    CipherSuite::SUITES.each_value { |suite| assert Ractor.shareable?(suite) }
    assert Ractor.shareable?(CipherSuite::SUITES)
    by_suite = { CipherSuite::TLS_AES_128_GCM_SHA256 => :a }
    assert_equal :a, by_suite[CipherSuite.find(0x1301)]
  end
end
