require "test_helper"
require "raiha/quic"
require "raiha/quic/test"

class RaihaNextQUICWireRetryTest < Minitest::Test
  Wire = Raiha::QUIC::Wire
  V1 = Raiha::QUIC::Version::V1
  V = Raiha::QUIC::Test::Vectors

  def retry_packet = Wire::Retry.new(version: V1, dcid: "".b, scid: V::Retry::SOURCE_CONNECTION_ID, token: V::Retry::TOKEN)

  # RFC 9001 appendix A.4: the answer to the client Initial of A.2, whose
  # connection ID the tag covers but the packet does not carry.
  def test_seal_rfc9001_retry
    assert_equal_bin V::Retry::PACKET, retry_packet.seal(V::Keys::DCID)
  end

  def test_the_tag_depends_on_the_original_dcid
    tag = ->(original_dcid) { retry_packet.seal(original_dcid).byteslice(-16, 16) }
    refute_equal tag.(V::Keys::DCID), tag.(V::Keys::DCID.succ)
    assert_equal_bin V::Retry::PACKET.byteslice(0, 20), retry_packet.seal(V::Keys::DCID.succ).byteslice(0, 20)
  end

  def test_parse_rfc9001_retry
    parsed = Wire::Packet.parse(V::Retry::PACKET, dcid_length: 8)
    assert_equal retry_packet.with(tag: V::Retry::PACKET.byteslice(-16, 16)), parsed
    assert parsed.authentic?(V::Keys::DCID)
    refute parsed.authentic?(V::Keys::DCID.succ)
  end

  # The tag covers the whole packet, the unused bits included, whatever
  # they are.
  def test_the_tag_covers_every_byte
    other_bits = retry_packet.with(unused: 0).seal(V::Keys::DCID)
    assert Wire::Packet.parse(other_bits, dcid_length: 8).authentic?(V::Keys::DCID)
    (0...V::Retry::PACKET.bytesize).each do |index|
      changed = V::Retry::PACKET.dup.tap { |bytes| bytes.setbyte(index, bytes.getbyte(index) ^ 0x01) }
      parsed = Wire::Packet.parse(changed, dcid_length: 8)
      refute parsed.is_a?(Wire::Retry) && parsed.authentic?(V::Keys::DCID), "byte #{index}"
    rescue Wire::Malformed
      # Some changes no longer make a Retry: a connection ID length past 20.
    end
  end

  def test_an_unsealed_retry_is_not_authentic
    refute retry_packet.authentic?(V::Keys::DCID)
  end

  def test_parse_rejects
    header = V::Retry::PACKET.byteslice(0, 15)
    assert_raises(Wire::Malformed) { Wire::Packet.parse(header + "t".b * 16, dcid_length: 8) }
    assert_raises(Wire::Malformed) { Wire::Packet.parse(header + "t".b * 10, dcid_length: 8) }
    assert_equal "t".b, Wire::Packet.parse(header + "t".b * 17, dcid_length: 8).token
  end

  def test_misuse
    assert_raises(ArgumentError) { retry_packet.with(token: "".b) }
    assert_raises(ArgumentError) { retry_packet.with(scid: "s".b * 21) }
    assert_raises(ArgumentError) { retry_packet.with(unused: 0x10) }
  end
end
