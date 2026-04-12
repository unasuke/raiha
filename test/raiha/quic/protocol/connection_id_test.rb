require "test_helper"
require "raiha/quic/protocol"

class RaihaQuicProtocolConnectionIDTest < Minitest::Test
  def test_generate
    cid = Raiha::Quic::Protocol::ConnectionID.generate
    assert_equal 8, cid.length
  end

  def test_generate_with_length
    cid = Raiha::Quic::Protocol::ConnectionID.generate(length: 16)
    assert_equal 16, cid.length
  end

  def test_from_bytes
    cid = Raiha::Quic::Protocol::ConnectionID.from_bytes("\x01\x02\x03\x04".b)
    assert_equal 4, cid.length
    assert_equal "\x01\x02\x03\x04".b, cid.serialize
  end

  def test_equality
    bytes = "\x01\x02\x03\x04".b
    cid1 = Raiha::Quic::Protocol::ConnectionID.new(bytes)
    cid2 = Raiha::Quic::Protocol::ConnectionID.new(bytes)
    assert_equal cid1, cid2
  end

  def test_to_s
    cid = Raiha::Quic::Protocol::ConnectionID.new("\xab\xcd".b)
    assert_equal "abcd", cid.to_s
  end

  def test_too_long
    assert_raises(ArgumentError) do
      Raiha::Quic::Protocol::ConnectionID.new("\x00" * 21)
    end
  end

  def test_max_length
    cid = Raiha::Quic::Protocol::ConnectionID.new("\x00" * 20)
    assert_equal 20, cid.length
  end
end
