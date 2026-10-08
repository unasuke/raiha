require "raiha/next/test_helper"
require "raiha/next/quic"

class RaihaNextQUICWireVersionNegotiationTest < Minitest::Test
  Wire = Raiha::Next::QUIC::Wire

  def negotiation = Wire::VersionNegotiation.new(dcid: "abc".b, scid: "".b, versions: [0x0000_0001, 0x0a1a_2a3a])

  def test_encode
    assert_equal_bin "\xc0\x00\x00\x00\x00\x03abc\x00\x00\x00\x00\x01\x0a\x1a\x2a\x3a".b, negotiation.encode
  end

  def test_parse
    assert_equal negotiation, Wire::Packet.parse(negotiation.encode, dcid_length: 8)
    # The first byte's other bits are unused, the fixed bit of version 1
    # among them.
    bytes = negotiation.encode.tap { |encoded| encoded.setbyte(0, 0x80) }
    assert_equal negotiation, Wire::Packet.parse(bytes, dcid_length: 8)
  end

  # Version Negotiation is the same in every version, and connection IDs
  # of other versions may be longer than version 1's 20 bytes.
  def test_long_connection_ids
    long = Wire::VersionNegotiation.new(dcid: "d".b * 255, scid: "s".b * 21, versions: [1])
    assert_equal long, Wire::Packet.parse(long.encode, dcid_length: 8)
    assert_raises(ArgumentError) { long.with(dcid: "d".b * 256) }
  end

  def test_parse_rejects
    encoded = negotiation.encode
    assert_raises(Wire::Malformed) { Wire::Packet.parse(encoded + "\x00".b, dcid_length: 8) }
    assert_raises(Wire::Malformed) { Wire::Packet.parse(encoded.byteslice(0, 7), dcid_length: 8) }
  end

  def test_versions_are_32_bits
    assert_raises(ArgumentError) { negotiation.with(versions: [1 << 32]) }
    assert_raises(ArgumentError) { negotiation.with(versions: [-1]) }
  end
end
