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

  def test_parse_rfc9001_packets
    client = Wire::Packet.parse(V::ClientInitial::PACKET, dcid_length: 8)
    assert_equal client_header, client.header
    assert_equal [0, 18, 1200], [client.offset, client.number_offset, client.end_offset]
    server = Wire::Packet.parse(V::ServerInitial::PACKET, dcid_length: 8)
    assert_equal server_header, server.header
    assert_equal [18, 135], [server.number_offset, server.end_offset]
    short = Wire::Packet.parse(V::ChaCha20ShortHeader::PACKET, dcid_length: 0)
    assert_equal Wire::ShortHeader.new(dcid: "".b, spin: false, key_phase: nil), short.header
    assert_equal [1, 21], [short.number_offset, short.end_offset]
  end

  # A long header packet ends where its Length field says; the next one
  # starts there.
  def test_parse_coalesced_packets
    datagram = V::ServerInitial::PACKET + V::ClientInitial::PACKET
    first = Wire::Packet.parse(datagram, dcid_length: 8)
    second = Wire::Packet.parse(datagram, offset: first.end_offset, dcid_length: 8)
    assert_equal server_header, first.header
    assert_equal client_header, second.header
    assert_equal [135, 135 + 18, datagram.bytesize], [second.offset, second.number_offset, second.end_offset]
  end

  def test_parse_short_header_fields
    header = Wire::ShortHeader.new(dcid: "c".b * 8, spin: true, key_phase: 1)
    sealed = Wire::Packet.seal(header, packet_number: 7, packet_number_length: 1, payload: "\0".b * 3, keys: chacha20_keys)
    parsed = Wire::Packet.parse(sealed, dcid_length: 8)
    assert_equal header.with(key_phase: nil), parsed.header
  end

  def test_parse_token
    header = client_header.with(token: "token".b)
    sealed = Wire::Packet.seal(header, packet_number: 0, packet_number_length: 1, payload: "\0".b * 3, keys: initial.client)
    assert_equal header, Wire::Packet.parse(sealed, dcid_length: 8).header
  end

  def test_parse_rejects
    client = V::ClientInitial::PACKET
    rejected = {
      "empty" => "".b,
      "fixed bit clear" => client.dup.tap { |bytes| bytes.setbyte(0, bytes.getbyte(0) & ~0x40) },
      "21-byte DCID" => "\xc0\x00\x00\x00\x01\x15".b + "x".b * 21 + "\x00\x00\x40\x20".b + "\0".b * 32,
      "Length past the datagram" => client.byteslice(0, 1199),
      "too short for a sample" => "\x40".b + "c".b * 8 + "\0".b * 19,
      "short header cut in its DCID" => "\x40\x01\x02".b
    }
    rejected.each do |name, bytes|
      assert_raises(Wire::Malformed, name) { Wire::Packet.parse(bytes, dcid_length: 8) }
    end
    assert_equal 29, Wire::Packet.parse("\x40".b + "c".b * 8 + "\0".b * 20, dcid_length: 8).end_offset
  end

  # RFC 9001 appendix A.2 and A.3, backwards: the unprotected header is the
  # associated data.
  def test_open_initial_packets
    client = Wire::Packet.parse(V::ClientInitial::PACKET, dcid_length: 8).unmask(initial.client.header_protection, largest: nil)
    assert_equal [client_header, 2], [client.header, client.packet_number]
    assert_equal_bin V::ClientInitial::HEADER, client.associated_data
    assert_equal_bin client_payload, client.open(initial.client.aead)
    s = V::ServerInitial
    server = Wire::Packet.parse(s::PACKET, dcid_length: 8).unmask(initial.server.header_protection, largest: nil)
    assert_equal [server_header, s::PACKET_NUMBER], [server.header, server.packet_number]
    assert_equal_bin s::HEADER, server.associated_data
    assert_equal_bin s::PAYLOAD, server.open(initial.server.aead)
  end

  # RFC 9001 appendix A.5: three bytes of packet number, decoded against
  # the largest one before it.
  def test_open_chacha20_short_header
    c = V::ChaCha20ShortHeader
    keys = chacha20_keys
    unmasked = Wire::Packet.parse(c::PACKET, dcid_length: 0).unmask(keys.header_protection, largest: c::PACKET_NUMBER - 1)
    assert_equal [Wire::ShortHeader.new(dcid: "".b, spin: false, key_phase: 0), c::PACKET_NUMBER], [unmasked.header, unmasked.packet_number]
    assert_equal_bin c::HEADER, unmasked.associated_data
    assert_equal_bin c::PAYLOAD, unmasked.open(keys.aead)
  end

  def test_key_phase_and_packet_number_come_back
    keys = chacha20_keys
    header = Wire::ShortHeader.new(dcid: "c".b * 8, spin: true, key_phase: 1)
    sealed = Wire::Packet.seal(header, packet_number: 0x1234, packet_number_length: 1, payload: "\x01\0\0".b, keys:)
    unmasked = Wire::Packet.parse(sealed, dcid_length: 8).unmask(keys.header_protection, largest: 0x1230)
    assert_equal [header, 0x1234], [unmasked.header, unmasked.packet_number]
    assert_equal_bin "\x01\0\0".b, unmasked.open(keys.aead)
  end

  # Under other keys, or with a byte changed, the payload does not open:
  # nil, and the packet is dropped.
  def test_what_does_not_open_is_nil
    packet = V::ClientInitial::PACKET
    assert_nil Wire::Packet.parse(packet, dcid_length: 8).unmask(initial.server.header_protection, largest: nil).open(initial.server.aead)
    tampered = packet.dup.tap { |bytes| bytes.setbyte(100, bytes.getbyte(100) ^ 1) }
    assert_nil Wire::Packet.parse(tampered, dcid_length: 8).unmask(initial.client.header_protection, largest: nil).open(initial.client.aead)
  end

  # RFC 9000 "Short Header Packets": reserved bits other than zero, found
  # once the packet opens, close the connection.
  def test_reserved_bits_are_a_protocol_violation
    keys = chacha20_keys
    reserving = Class.new(Wire::ShortHeader) { def first_byte(length) = super | 0x08 }
    sealed = Wire::Packet.seal(reserving.new(dcid: "".b), packet_number: 0, packet_number_length: 1, payload: "\x01\0\0".b, keys:)
    unmasked = Wire::Packet.parse(sealed, dcid_length: 0).unmask(keys.header_protection, largest: nil)
    error = assert_raises(Wire::Malformed) { unmasked.open(keys.aead) }
    assert_equal QUIC::ErrorCode::PROTOCOL_VIOLATION, error.code
    # A packet that does not open is dropped before the bits count.
    assert_nil unmasked.open(QUIC::Crypto::Keys.derive(suite: Raiha::Next::TLS::CipherSuite::TLS_CHACHA20_POLY1305_SHA256, secret: "\0".b * 32, version: V1).aead)
  end

  # The datagram is left as it was, so the packets coalesced with this one
  # still read.
  def test_unmask_leaves_the_datagram_alone
    datagram = V::ClientInitial::PACKET.dup
    Wire::Packet.parse(datagram, dcid_length: 8).unmask(initial.client.header_protection, largest: nil)
    assert_equal_bin V::ClientInitial::PACKET, datagram
  end

  # The packet type `Wire::Frame.parse` takes.
  def test_header_types
    assert_equal [:initial, :one_rtt], [client_header.type, Wire::ShortHeader.new(dcid: "".b).type]
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
