require "raiha/next/test_helper"
require "raiha/next/quic"
require "raiha/next/quic/test"

class RaihaNextQUICCryptoKeysTest < Minitest::Test
  Keys = Raiha::Next::QUIC::Crypto::Keys
  Suite = Raiha::Next::TLS::CipherSuite
  V1 = Raiha::Next::QUIC::Version::V1
  V = Raiha::Next::QUIC::Test::Vectors

  # RFC 9001 appendix A.5: a 1-RTT secret of ChaCha20-Poly1305.
  def test_chacha20_poly1305
    c = V::ChaCha20ShortHeader
    keys = Keys.derive(suite: Suite::TLS_CHACHA20_POLY1305_SHA256, secret: c::SECRET, version: V1)
    assert_equal_bin c::CIPHERTEXT, keys.aead.seal(packet_number: c::PACKET_NUMBER, header: c::HEADER, plaintext: c::PAYLOAD)
    assert_equal_bin c::MASK, keys.header_protection.mask(c::SAMPLE)
  end

  # RFC 9001 appendix A.1 and A.3: the server's Initial secret.
  def test_aes_128_gcm
    s = V::ServerInitial
    keys = Keys.derive(suite: Suite::TLS_AES_128_GCM_SHA256, secret: V::Keys::SERVER_INITIAL_SECRET, version: V1)
    assert_equal_bin s::PACKET.byteslice(s::HEADER.bytesize..),
      keys.aead.seal(packet_number: s::PACKET_NUMBER, header: s::HEADER, plaintext: s::PAYLOAD)
    assert_equal_bin s::MASK, keys.header_protection.mask(s::SAMPLE)
  end

  # The labels come from the version, so another prefix is other keys.
  def test_labels_follow_the_version
    c = V::ChaCha20ShortHeader
    other = V1.with(label_prefix: "quicv2")
    keys = Keys.derive(suite: Suite::TLS_CHACHA20_POLY1305_SHA256, secret: c::SECRET, version: other)
    refute_equal c::CIPHERTEXT, keys.aead.seal(packet_number: c::PACKET_NUMBER, header: c::HEADER, plaintext: c::PAYLOAD)
    refute_equal c::MASK, keys.header_protection.mask(c::SAMPLE)
  end
end
