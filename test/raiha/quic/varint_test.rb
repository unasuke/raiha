require "test_helper"
require "raiha/quic/varint"

class RaihaQuicVarintTest < Minitest::Test
  def test_encode_1_byte
    assert_equal "\x00".b, Raiha::Quic::Varint.encode(0)
    assert_equal "\x25".b, Raiha::Quic::Varint.encode(37)
    assert_equal "\x3f".b, Raiha::Quic::Varint.encode(63)
  end

  def test_encode_2_bytes
    assert_equal "\x40\x40".b, Raiha::Quic::Varint.encode(64)
    assert_equal "\x7b\xbd".b, Raiha::Quic::Varint.encode(15293)
  end

  def test_encode_4_bytes
    assert_equal "\x80\x00\x40\x00".b, Raiha::Quic::Varint.encode(16384)
    assert_equal "\x9d\x7f\x3e\x7d".b, Raiha::Quic::Varint.encode(494878333)
  end

  def test_encode_8_bytes
    assert_equal "\xc2\x19\x7c\x5e\xff\x14\xe8\x8c".b, Raiha::Quic::Varint.encode(151288809941952652)
  end

  def test_decode_1_byte
    assert_equal 37, Raiha::Quic::Varint.decode(StringIO.new("\x25"))
  end

  def test_decode_2_bytes
    assert_equal 15293, Raiha::Quic::Varint.decode(StringIO.new("\x7b\xbd"))
  end

  def test_decode_4_bytes
    assert_equal 494878333, Raiha::Quic::Varint.decode(StringIO.new("\x9d\x7f\x3e\x7d"))
  end

  def test_decode_8_bytes
    assert_equal 151288809941952652, Raiha::Quic::Varint.decode(StringIO.new("\xc2\x19\x7c\x5e\xff\x14\xe8\x8c"))
  end

  def test_roundtrip
    [0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, (1 << 62) - 1].each do |value|
      encoded = Raiha::Quic::Varint.encode(value)
      decoded = Raiha::Quic::Varint.decode(StringIO.new(encoded))
      assert_equal value, decoded, "Roundtrip failed for #{value}"
    end
  end

  def test_byte_size
    assert_equal 1, Raiha::Quic::Varint.byte_size(0)
    assert_equal 1, Raiha::Quic::Varint.byte_size(63)
    assert_equal 2, Raiha::Quic::Varint.byte_size(64)
    assert_equal 2, Raiha::Quic::Varint.byte_size(16383)
    assert_equal 4, Raiha::Quic::Varint.byte_size(16384)
    assert_equal 8, Raiha::Quic::Varint.byte_size(1073741824)
  end

  def test_encode_negative_raises
    assert_raises(ArgumentError) { Raiha::Quic::Varint.encode(-1) }
  end

  def test_encode_too_large_raises
    assert_raises(ArgumentError) { Raiha::Quic::Varint.encode((1 << 62)) }
  end
end
