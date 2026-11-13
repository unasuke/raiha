require "test_helper"
require "raiha/quic"
require "raiha/quic/test"

class RaihaNextQUICCryptoInitialTest < Minitest::Test
  Initial = Raiha::QUIC::Crypto::Initial
  V1 = Raiha::QUIC::Version::V1
  V = Raiha::QUIC::Test::Vectors

  def ciphertext_of(vector) = vector::PACKET.byteslice(vector::HEADER.bytesize..)

  # RFC 9001 appendix A.1, checked through the packets of A.2 and A.3.
  def test_rfc9001_keys
    initial = Initial.derive(dcid: V::Keys::DCID, version: V1)
    c = V::ClientInitial
    plaintext = c::FRAMES.ljust(c::PAYLOAD_LENGTH, "\0".b)
    assert_equal_bin ciphertext_of(c), initial.client.aead.seal(packet_number: c::PACKET_NUMBER, header: c::HEADER, plaintext:)
    assert_equal_bin c::MASK, initial.client.header_protection.mask(c::SAMPLE)
    s = V::ServerInitial
    assert_equal_bin ciphertext_of(s), initial.server.aead.seal(packet_number: s::PACKET_NUMBER, header: s::HEADER, plaintext: s::PAYLOAD)
    assert_equal_bin s::MASK, initial.server.header_protection.mask(s::SAMPLE)
  end

  # Both ends derive the same keys: the server opens what the client sealed.
  def test_both_ends_agree
    c = V::ClientInitial
    server_side = Initial.derive(dcid: V::Keys::DCID, version: V1)
    opened = server_side.client.aead.open(packet_number: c::PACKET_NUMBER, header: c::HEADER, ciphertext: ciphertext_of(c))
    assert_equal_bin c::FRAMES, opened.byteslice(0, c::FRAMES.bytesize)
  end

  def test_the_salt_and_the_dcid_matter
    c = V::ClientInitial
    plaintext = c::FRAMES
    sealed = ->(initial) { initial.client.aead.seal(packet_number: 0, header: c::HEADER, plaintext:) }
    reference = sealed.(Initial.derive(dcid: V::Keys::DCID, version: V1))
    refute_equal reference, sealed.(Initial.derive(dcid: V::Keys::DCID.succ, version: V1))
    refute_equal reference, sealed.(Initial.derive(dcid: V::Keys::DCID, version: V1.with(initial_salt: "\0".b * 20)))
  end
end
