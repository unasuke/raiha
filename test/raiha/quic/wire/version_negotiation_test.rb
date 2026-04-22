require "test_helper"
require "raiha/quic/wire/version_negotiation"

class RaihaQuicWireVersionNegotiationTest < Minitest::Test
  VN = Raiha::Quic::Wire::VersionNegotiation

  def test_match_true_for_long_header_with_zero_version
    packet = VN.build(
      src_connection_id: "\xaa\xbb".b,
      dest_connection_id: "\xcc\xdd".b,
      supported_versions: [0x00000001]
    )
    assert VN.match?(packet)
  end

  def test_match_false_for_non_long_header
    # short-header packet (bit 7 = 0)
    data = ("\x40".b + "\x00".b * 20)
    refute VN.match?(data)
  end

  def test_match_false_for_non_zero_version
    data = ("\xc0".b + "\x00\x00\x00\x01".b + "\x00".b * 20)
    refute VN.match?(data)
  end

  def test_match_false_for_short_datagram
    refute VN.match?("\x80".b)
  end

  def test_parse_returns_connection_ids_and_versions
    scid = "\x01\x02\x03\x04".b
    dcid = "\x0a\x0b".b
    versions = [0x00000001, 0x6b3343cf]
    packet = VN.build(
      src_connection_id: scid,
      dest_connection_id: dcid,
      supported_versions: versions
    )

    parsed = VN.parse(packet)
    refute_nil parsed
    assert_equal dcid, parsed[:dest_connection_id]
    assert_equal scid, parsed[:src_connection_id]
    assert_equal versions, parsed[:supported_versions]
  end

  def test_parse_returns_nil_for_non_vn
    data = ("\xc0".b + "\x00\x00\x00\x01".b + "\x00".b * 20)
    assert_nil VN.parse(data)
  end

  def test_parse_rejects_non_multiple_of_four_trailing_bytes
    scid = "\x01".b
    dcid = "\x0a".b
    packet = VN.build(
      src_connection_id: scid,
      dest_connection_id: dcid,
      supported_versions: [0x00000001]
    )
    truncated = packet.byteslice(0, packet.bytesize - 1)
    assert_nil VN.parse(truncated)
  end
end
