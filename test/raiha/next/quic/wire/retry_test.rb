require "raiha/next/test_helper"
require "raiha/next/quic"
require "raiha/next/quic/test"

class RaihaNextQUICWireRetryTest < Minitest::Test
  Wire = Raiha::Next::QUIC::Wire
  V1 = Raiha::Next::QUIC::Version::V1
  V = Raiha::Next::QUIC::Test::Vectors

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

  def test_misuse
    assert_raises(ArgumentError) { retry_packet.with(token: "".b) }
    assert_raises(ArgumentError) { retry_packet.with(scid: "s".b * 21) }
    assert_raises(ArgumentError) { retry_packet.with(unused: 0x10) }
  end
end
