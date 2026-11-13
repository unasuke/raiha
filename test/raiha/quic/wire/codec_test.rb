require "test_helper"
require "raiha/quic"

class RaihaQUICWireCodecTest < Minitest::Test
  Wire = Raiha::QUIC::Wire
  ErrorCode = Raiha::QUIC::ErrorCode

  def hex(s) = [s.delete(" ")].pack("H*")

  # RFC 9000 appendix A.1.
  def test_rfc9000_samples
    {
      "c2197c5eff14e88c" => [151_288_809_941_952_652, 8],
      "9d7f3e7d" => [494_878_333, 4],
      "7bbd" => [15_293, 2],
      "25" => [37, 1],
      "4025" => [37, 2]
    }.each do |bytes, expected|
      assert_equal expected, Wire::Reader.new(hex(bytes)).varint_with_size, bytes
    end
    assert_equal_bin hex("c2197c5eff14e88c"), Wire::Varint.encode(151_288_809_941_952_652)
    assert_equal_bin hex("25"), Wire::Varint.encode(37)
  end

  def test_round_trip_at_each_boundary
    [0, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, Wire::Varint::MAX].each do |value|
      encoded = Wire::Varint.encode(value)
      assert_equal Wire::Varint.size(value), encoded.bytesize
      assert_equal value, Wire::Reader.new(encoded).varint
    end
  end

  def test_out_of_range_is_our_mistake
    [-1, Wire::Varint::MAX + 1, 1.5, nil].each do |value|
      assert_raises(ArgumentError) { Wire::Varint.encode(value) }
    end
  end

  def test_truncated
    ["", "\x40", "\x80\x00\x00", "\xc0\x00\x00\x00\x00\x00\x00"].each do |bytes|
      error = assert_raises(Wire::Truncated) { Wire::Reader.new(bytes.b).varint }
      assert_equal ErrorCode::FRAME_ENCODING_ERROR, error.code
    end
    reader = Wire::Reader.new("abc".b)
    assert_raises(Wire::Truncated) { reader.bytes(4) }
    assert_equal 0, reader.offset
  end

  def test_limits_and_sub_readers
    reader = Wire::Reader.new("\x01\x02\x03\x04\x05".b, 1, 4)
    assert_equal 3, reader.remaining
    sub = reader.sub(2)
    assert_equal [2, 3], [sub.u8, sub.u8]
    assert sub.eof?
    assert_raises(Wire::Truncated) { sub.u8 }
    assert_equal 4, reader.u8
    assert reader.eof?
    assert_raises(Wire::Truncated) { reader.sub(1) }
  end

  def test_writer
    writer = Wire::Writer.new.u8(1).u16(0x0203).u32(0x04050607).varint(16_384).bytes("xy")
    assert_equal_bin "\x01\x02\x03\x04\x05\x06\x07\x80\x00\x40\x00xy".b, writer.to_s
    assert_equal 13, writer.bytesize
  end

  def test_malformed_carries_its_code
    assert_equal ErrorCode::TRANSPORT_PARAMETER_ERROR, Wire::Malformed.new("x", code: ErrorCode::TRANSPORT_PARAMETER_ERROR).code
  end
end
