require "raiha/next/test_helper"
require "raiha/next/quic"
require "raiha/next/quic/test"

class RaihaNextQUICWirePacketTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
  Wire = QUIC::Wire
  V1 = QUIC::Version::V1
  V = QUIC::Test::Vectors

  def initial = QUIC::Crypto::Initial.derive(dcid: V::Keys::DCID, version: V1)

  def client_header = Wire::LongHeader.new(type: :initial, version: V1, dcid: V::Keys::DCID, scid: "".b, token: "".b)

  # The server's connection ID, as its header in RFC 9001 appendix A.3
  # carries it.
  def server_header = Wire::LongHeader.new(type: :initial, version: V1, dcid: "".b, scid: V::ServerInitial::HEADER.byteslice(7, 8))

  def client_payload = V::ClientInitial::FRAMES.ljust(V::ClientInitial::PAYLOAD_LENGTH, "\0".b)

  def chacha20_keys
    QUIC::Crypto::Keys.derive(suite: Raiha::Next::TLS::CipherSuite::TLS_CHACHA20_POLY1305_SHA256, secret: V::ChaCha20ShortHeader::SECRET, version: V1)
  end

  # RFC 9001 appendix A.2: the packet number in four bytes.
  def test_seal_client_initial
    sealed = Wire::Packet.seal(client_header, packet_number: 2, packet_number_length: 4, payload: client_payload, keys: initial.client)
    assert_equal_bin V::ClientInitial::PACKET, sealed
  end

  # RFC 9001 appendix A.3.
  def test_seal_server_initial
    s = V::ServerInitial
    sealed = Wire::Packet.seal(server_header, packet_number: s::PACKET_NUMBER, packet_number_length: 2, payload: s::PAYLOAD, keys: initial.server)
    assert_equal_bin s::PACKET, sealed
  end

  # RFC 9001 appendix A.5: a short header with an empty connection ID.
  def test_seal_chacha20_short_header
    c = V::ChaCha20ShortHeader
    sealed = Wire::Packet.seal(Wire::ShortHeader.new(dcid: "".b), packet_number: c::PACKET_NUMBER, packet_number_length: 3,
      payload: c::PAYLOAD, keys: chacha20_keys)
    assert_equal_bin c::PACKET, sealed
  end

  # The sample needs 4 bytes of packet number and payload before the tag.
  def test_seal_needs_room_for_the_sample
    header = Wire::ShortHeader.new(dcid: "".b)
    assert_raises(ArgumentError) { Wire::Packet.seal(header, packet_number: 0, packet_number_length: 1, payload: "ab".b, keys: chacha20_keys) }
    assert_equal 1 + 1 + 3 + 16, Wire::Packet.seal(header, packet_number: 0, packet_number_length: 1, payload: "abc".b, keys: chacha20_keys).bytesize
    assert_raises(ArgumentError) { Wire::Packet.seal(header, packet_number: 0, packet_number_length: 5, payload: "abcd".b, keys: chacha20_keys) }
  end

  def test_first_bytes
    assert_equal 0xc3, client_header.first_byte(4)
    assert_equal 0xe0, client_header.with(type: :handshake).first_byte(1)
    assert_equal 0xd1, client_header.with(type: :zero_rtt).first_byte(2)
    assert_equal 0x40, Wire::ShortHeader.new(dcid: "".b).first_byte(1)
    assert_equal 0x67, Wire::ShortHeader.new(dcid: "".b, spin: true, key_phase: 1).first_byte(4)
    assert_raises(ArgumentError) { Wire::ShortHeader.new(dcid: "".b, key_phase: 2).first_byte(1) }
  end

  def test_header_misuse
    assert_raises(ArgumentError) { client_header.with(type: :retry) }
    assert_raises(ArgumentError) { client_header.with(type: :handshake, token: "t".b) }
    assert_raises(ArgumentError) { client_header.with(dcid: "x".b * 21) }
    assert_raises(ArgumentError) { client_header.with(scid: "x".b * 21) }
    assert_raises(ArgumentError) { Wire::ShortHeader.new(dcid: "x".b * 21) }
    assert_equal 20, client_header.with(dcid: "x".b * 20).dcid.bytesize
  end
end
