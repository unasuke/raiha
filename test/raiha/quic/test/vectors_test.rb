require "test_helper"
require "raiha/quic/test"

# The RFC 9001 appendix A values as taken from the text, checked against
# each other and against the TLS layer's key schedule, before any QUIC code
# uses them.
class RaihaQUICTestVectorsTest < Minitest::Test
  V = Raiha::QUIC::Test::Vectors
  KeySchedule = Raiha::TLS::KeySchedule

  def expand(secret, label, length) = KeySchedule.expand_label(secret:, label:, length:, hash: :sha256)

  def test_keys_follow_from_the_salt
    k = V::Keys
    initial = KeySchedule.extract(salt: Raiha::QUIC::Version::V1.initial_salt, ikm: k::DCID, hash: :sha256)
    assert_equal_bin k::INITIAL_SECRET, initial
    assert_equal_bin k::CLIENT_INITIAL_SECRET, expand(initial, "client in", 32)
    assert_equal_bin k::SERVER_INITIAL_SECRET, expand(initial, "server in", 32)
    assert_equal_bin k::CLIENT_KEY, expand(k::CLIENT_INITIAL_SECRET, "quic key", 16)
    assert_equal_bin k::SERVER_HP, expand(k::SERVER_INITIAL_SECRET, "quic hp", 16)
    c = V::ChaCha20ShortHeader
    assert_equal_bin c::KU, expand(c::SECRET, "quic ku", 32)
  end

  def test_shapes
    client = V::ClientInitial
    assert_equal 1200, client::PACKET.bytesize
    # The Length field, after the empty SCID and token, covers the packet
    # number, the payload and the tag.
    assert_equal 4 + client::PAYLOAD_LENGTH + 16, client::HEADER.byteslice(16, 2).unpack1("n") & 0x3fff
    assert client::PACKET.start_with?(client::PROTECTED_HEADER)
    assert_equal 135, V::ServerInitial::PACKET.bytesize
    assert V::ServerInitial::PACKET.start_with?(V::ServerInitial::PROTECTED_HEADER)
    c = V::ChaCha20ShortHeader
    assert_equal_bin c::PROTECTED_HEADER + c::CIPHERTEXT, c::PACKET
    retry_packet = V::Retry::PACKET
    assert_equal_bin "\xff\x00\x00\x00\x01\x00\x08".b + V::Retry::SOURCE_CONNECTION_ID + V::Retry::TOKEN, retry_packet.byteslice(0, 20)
    assert_equal 36, retry_packet.bytesize
  end

  def test_frozen
    [V::Keys::DCID, V::ClientInitial::PACKET, V::Retry::TOKEN].each do |value|
      assert value.frozen?
      assert_equal Encoding::BINARY, value.encoding
    end
  end
end
