require "test_helper"
require "raiha/quic/protocol"

class RaihaQuicProtocolPerspectiveTest < Minitest::Test
  def test_opposite
    assert_equal :server, Raiha::Quic::Protocol::Perspective.opposite(:client)
    assert_equal :client, Raiha::Quic::Protocol::Perspective.opposite(:server)
  end

  def test_opposite_invalid
    assert_raises(ArgumentError) do
      Raiha::Quic::Protocol::Perspective.opposite(:invalid)
    end
  end

  def test_client?
    assert Raiha::Quic::Protocol::Perspective.client?(:client)
    refute Raiha::Quic::Protocol::Perspective.client?(:server)
  end

  def test_server?
    assert Raiha::Quic::Protocol::Perspective.server?(:server)
    refute Raiha::Quic::Protocol::Perspective.server?(:client)
  end
end
