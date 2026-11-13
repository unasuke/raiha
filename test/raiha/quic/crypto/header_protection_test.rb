require "test_helper"
require "raiha/quic"
require "raiha/quic/test"

class RaihaNextQUICCryptoHeaderProtectionTest < Minitest::Test
  HeaderProtection = Raiha::Next::QUIC::Crypto::HeaderProtection
  Suite = Raiha::Next::TLS::CipherSuite
  V = Raiha::Next::QUIC::Test::Vectors

  # RFC 9001 appendix A.2 and A.3.
  def test_aes
    client = HeaderProtection.new(suite: Suite::TLS_AES_128_GCM_SHA256, key: V::Keys::CLIENT_HP)
    assert_equal_bin V::ClientInitial::MASK, client.mask(V::ClientInitial::SAMPLE)
    server = HeaderProtection.new(suite: Suite::TLS_AES_128_GCM_SHA256, key: V::Keys::SERVER_HP)
    assert_equal_bin V::ServerInitial::MASK, server.mask(V::ServerInitial::SAMPLE)
    # The context is reused: the next sample stands on its own.
    assert_equal_bin V::ClientInitial::MASK, client.mask(V::ClientInitial::SAMPLE)
  end

  # RFC 9001 appendix A.5.
  def test_chacha20
    c = V::ChaCha20ShortHeader
    hp = HeaderProtection.new(suite: Suite::TLS_CHACHA20_POLY1305_SHA256, key: c::HP)
    assert_equal_bin c::MASK, hp.mask(c::SAMPLE)
    other = hp.mask(V::ClientInitial::SAMPLE)
    refute_equal c::MASK, other
    assert_equal 5, other.bytesize
    assert_equal_bin c::MASK, hp.mask(c::SAMPLE)
  end

  def test_aes_256
    hp = HeaderProtection.new(suite: Suite::TLS_AES_256_GCM_SHA384, key: "k".b * 32)
    mask = hp.mask(V::ClientInitial::SAMPLE)
    assert_equal 5, mask.bytesize
    refute_equal mask, HeaderProtection.new(suite: Suite::TLS_AES_256_GCM_SHA384, key: "j".b * 32).mask(V::ClientInitial::SAMPLE)
  end

  def test_lengths_are_checked
    assert_raises(ArgumentError) { HeaderProtection.new(suite: Suite::TLS_AES_256_GCM_SHA384, key: V::Keys::CLIENT_HP) }
    hp = HeaderProtection.new(suite: Suite::TLS_AES_128_GCM_SHA256, key: V::Keys::CLIENT_HP)
    assert_raises(ArgumentError) { hp.mask("x".b * 15) }
    assert_raises(ArgumentError) { hp.mask("x".b * 17) }
  end

  def test_inspect_leaves_the_key_out
    hp = HeaderProtection.new(suite: Suite::TLS_AES_128_GCM_SHA256, key: V::Keys::CLIENT_HP)
    assert_match(/@name="aes-128-ecb"/, hp.inspect)
    refute_includes hp.inspect, "@cipher"
  end
end
