require "test_helper"
require "raiha/quic"
require "raiha/quic/test"

class RaihaNextQUICCryptoAEADTest < Minitest::Test
  AEAD = Raiha::QUIC::Crypto::AEAD
  Suite = Raiha::TLS::CipherSuite
  V = Raiha::QUIC::Test::Vectors

  def client_aead = AEAD.new(suite: Suite::TLS_AES_128_GCM_SHA256, key: V::Keys::CLIENT_KEY, iv: V::Keys::CLIENT_IV)

  # The bytes after the unprotected header: header protection changes only
  # the header.
  def ciphertext_of(vector) = vector::PACKET.byteslice(vector::HEADER.bytesize..)

  def client_plaintext = V::ClientInitial::FRAMES.ljust(V::ClientInitial::PAYLOAD_LENGTH, "\0".b)

  # RFC 9001 appendix A.2.
  def test_client_initial
    c = V::ClientInitial
    sealed = client_aead.seal(packet_number: c::PACKET_NUMBER, header: c::HEADER, plaintext: client_plaintext)
    assert_equal_bin ciphertext_of(c), sealed
    assert_equal_bin client_plaintext, client_aead.open(packet_number: c::PACKET_NUMBER, header: c::HEADER, ciphertext: sealed)
  end

  # RFC 9001 appendix A.3.
  def test_server_initial
    s = V::ServerInitial
    aead = AEAD.new(suite: Suite::TLS_AES_128_GCM_SHA256, key: V::Keys::SERVER_KEY, iv: V::Keys::SERVER_IV)
    assert_equal_bin ciphertext_of(s), aead.seal(packet_number: s::PACKET_NUMBER, header: s::HEADER, plaintext: s::PAYLOAD)
  end

  # RFC 9001 appendix A.5: the whole 62-bit packet number goes into the
  # nonce, not the two bytes on the wire.
  def test_chacha20_poly1305
    c = V::ChaCha20ShortHeader
    aead = AEAD.new(suite: Suite::TLS_CHACHA20_POLY1305_SHA256, key: c::KEY, iv: c::IV)
    assert_equal_bin c::CIPHERTEXT, aead.seal(packet_number: c::PACKET_NUMBER, header: c::HEADER, plaintext: c::PAYLOAD)
    assert_equal_bin c::PAYLOAD, aead.open(packet_number: c::PACKET_NUMBER, header: c::HEADER, ciphertext: c::CIPHERTEXT)
  end

  def test_what_does_not_authenticate_is_nil
    c = V::ClientInitial
    aead = client_aead
    sealed = ciphertext_of(c)
    forged = sealed.dup.tap { |bytes| bytes.setbyte(0, bytes.getbyte(0) ^ 1) }
    assert_nil aead.open(packet_number: c::PACKET_NUMBER, header: c::HEADER, ciphertext: forged)
    assert_nil aead.open(packet_number: c::PACKET_NUMBER + 1, header: c::HEADER, ciphertext: sealed)
    assert_nil aead.open(packet_number: c::PACKET_NUMBER, header: c::HEADER.succ, ciphertext: sealed)
    assert_nil aead.open(packet_number: c::PACKET_NUMBER, header: c::HEADER, ciphertext: sealed.byteslice(0, 15))
    # The context is still good after a failure.
    assert_equal_bin client_plaintext, aead.open(packet_number: c::PACKET_NUMBER, header: c::HEADER, ciphertext: sealed)
  end

  def test_empty_plaintext_is_the_tag
    sealed = client_aead.seal(packet_number: 0, header: "h".b, plaintext: "".b)
    assert_equal 16, sealed.bytesize
    assert_equal_bin "".b, client_aead.open(packet_number: 0, header: "h".b, ciphertext: sealed)
  end

  def test_key_and_iv_lengths_are_checked
    assert_raises(ArgumentError) { AEAD.new(suite: Suite::TLS_AES_256_GCM_SHA384, key: V::Keys::CLIENT_KEY, iv: V::Keys::CLIENT_IV) }
    assert_raises(ArgumentError) { AEAD.new(suite: Suite::TLS_AES_128_GCM_SHA256, key: V::Keys::CLIENT_KEY, iv: "x".b * 8) }
  end

  def test_inspect_leaves_the_key_out
    refute_includes client_aead.inspect, V::Keys::CLIENT_KEY.inspect[1..-2]
    refute_includes client_aead.inspect, "@key"
  end
end
