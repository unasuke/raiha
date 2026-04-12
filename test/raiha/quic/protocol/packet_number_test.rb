require "test_helper"
require "raiha/quic/protocol"

class RaihaQuicProtocolPacketNumberTest < Minitest::Test
  def test_initialize
    pn = Raiha::Quic::Protocol::PacketNumber.new(42)
    assert_equal 42, pn.value
  end

  def test_increment
    pn = Raiha::Quic::Protocol::PacketNumber.new(0)
    assert_equal 1, pn.increment.value
  end

  def test_comparable
    pn1 = Raiha::Quic::Protocol::PacketNumber.new(1)
    pn2 = Raiha::Quic::Protocol::PacketNumber.new(2)
    assert pn1 < pn2
    assert pn2 > pn1
  end

  def test_overflow
    assert_raises(ArgumentError) do
      Raiha::Quic::Protocol::PacketNumber.new((1 << 62))
    end
  end

  def test_negative
    assert_raises(ArgumentError) do
      Raiha::Quic::Protocol::PacketNumber.new(-1)
    end
  end

  def test_encode_1_byte
    pn = Raiha::Quic::Protocol::PacketNumber.new(10)
    result = pn.encode(0)
    assert_equal 1, result[:bytes]
  end

  def test_decode_no_wrap
    pn = Raiha::Quic::Protocol::PacketNumber.decode(0x9b32, 16, 0xa82f30)
    assert_equal 0xa89b32, pn.value
  end

  def test_decode_simple
    pn = Raiha::Quic::Protocol::PacketNumber.decode(1, 8, 0)
    assert_equal 1, pn.value
  end

  def test_packet_number_space
    assert_equal :initial, Raiha::Quic::Protocol::PacketNumberSpace::INITIAL
    assert_equal :handshake, Raiha::Quic::Protocol::PacketNumberSpace::HANDSHAKE
    assert_equal :application_data, Raiha::Quic::Protocol::PacketNumberSpace::APPLICATION_DATA
  end
end
