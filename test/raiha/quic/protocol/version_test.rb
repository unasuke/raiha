require "test_helper"
require "raiha/quic/protocol"

class RaihaQuicProtocolVersionTest < Minitest::Test
  def test_v1_constant
    assert_equal 0x00000001, Raiha::Quic::Protocol::Version::V1
  end

  def test_v2_constant
    assert_equal 0x6b3343cf, Raiha::Quic::Protocol::Version::V2
  end

  def test_supported
    assert Raiha::Quic::Protocol::Version.supported?(Raiha::Quic::Protocol::Version::V1)
    assert Raiha::Quic::Protocol::Version.supported?(Raiha::Quic::Protocol::Version::V2)
    refute Raiha::Quic::Protocol::Version.supported?(0xdeadbeef)
  end

  def test_to_s
    assert_equal "QUIC v1", Raiha::Quic::Protocol::Version.to_s(Raiha::Quic::Protocol::Version::V1)
    assert_equal "QUIC v2", Raiha::Quic::Protocol::Version.to_s(Raiha::Quic::Protocol::Version::V2)
    assert_match(/Unknown/, Raiha::Quic::Protocol::Version.to_s(0xdeadbeef))
  end
end
