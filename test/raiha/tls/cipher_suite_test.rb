require "test_helper"
require "raiha/tls/cipher_suite"

class RaihaTLSCipherSuiteTest < Minitest::Test
  def test_initialize
    known_cipher_suites = %i(
      TLS_AES_128_GCM_SHA256
      TLS_AES_256_GCM_SHA384
      TLS_CHACHA20_POLY1305_SHA256
      TLS_AES_128_CCM_SHA256
      TLS_AES_128_CCM_8_SHA256
    )
    known_cipher_suites.each do |cipher_suite|
      assert_equal ::Raiha::TLS::CipherSuite, ::Raiha::TLS::CipherSuite.new(cipher_suite).class
    end

    unknown_cipher_suite = :TLS_UNKNOWN_CIPHER_SUITE
    assert_raises do
      ::Raiha::TLS::CipherSuite.new(unknown_cipher_suite)
    end
  end

  def test_value
    assert_equal "\x13\x01", ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256).value
    assert_equal "\x13\x02", ::Raiha::TLS::CipherSuite.new(:TLS_AES_256_GCM_SHA384).value
    assert_equal "\x13\x03", ::Raiha::TLS::CipherSuite.new(:TLS_CHACHA20_POLY1305_SHA256).value
    assert_equal "\x13\x04", ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_CCM_SHA256).value
    assert_equal "\x13\x05", ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_CCM_8_SHA256).value
  end

  def test_serialize
    assert_equal_bin "\x13\x01", ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256).serialize
    assert_equal_bin "\x13\x02", ::Raiha::TLS::CipherSuite.new(:TLS_AES_256_GCM_SHA384).serialize
    assert_equal_bin "\x13\x03", ::Raiha::TLS::CipherSuite.new(:TLS_CHACHA20_POLY1305_SHA256).serialize
    assert_equal_bin "\x13\x04", ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_CCM_SHA256).serialize
    assert_equal_bin "\x13\x05", ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_CCM_8_SHA256).serialize
  end

  def test_supported
    assert ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256).supported?
    assert ::Raiha::TLS::CipherSuite.new(:TLS_AES_256_GCM_SHA384).supported?
    assert ::Raiha::TLS::CipherSuite.new(:TLS_CHACHA20_POLY1305_SHA256).supported?

    refute ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_CCM_SHA256).supported?
    refute ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_CCM_8_SHA256).supported?
  end

  def test_hash_algorithm
    assert_equal "SHA256", ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256).hash_algorithm
    assert_equal "SHA256", ::Raiha::TLS::CipherSuite.new(:TLS_CHACHA20_POLY1305_SHA256).hash_algorithm
    assert_equal "SHA384", ::Raiha::TLS::CipherSuite.new(:TLS_AES_256_GCM_SHA384).hash_algorithm

    assert_raises do
      ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_CCM_8_SHA256).hash_algorithm
    end
  end

  def test_aead_algorithm
    assert_equal "aes-128-gcm", ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256).aead_algorithm
    assert_equal "aes-256-gcm", ::Raiha::TLS::CipherSuite.new(:TLS_AES_256_GCM_SHA384).aead_algorithm
    assert_equal "chacha20-poly1305", ::Raiha::TLS::CipherSuite.new(:TLS_CHACHA20_POLY1305_SHA256).aead_algorithm
    assert_equal "aes-128-ccm", ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_CCM_SHA256).aead_algorithm

    assert_raises do
      ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_CCM_8_SHA256).aead_algorithm
    end
  end

  def test_deserialize
    assert_equal :TLS_AES_128_GCM_SHA256, ::Raiha::TLS::CipherSuite.deserialize("\x13\x01").name
    assert_equal :TLS_AES_256_GCM_SHA384, ::Raiha::TLS::CipherSuite.deserialize("\x13\x02").name
    assert_equal :TLS_CHACHA20_POLY1305_SHA256, ::Raiha::TLS::CipherSuite.deserialize("\x13\x03").name
    assert_equal :TLS_AES_128_CCM_SHA256, ::Raiha::TLS::CipherSuite.deserialize("\x13\x04").name
    assert_equal :TLS_AES_128_CCM_8_SHA256, ::Raiha::TLS::CipherSuite.deserialize("\x13\x05").name
  end
end
