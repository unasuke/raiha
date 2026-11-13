require "test_helper"
require "raiha/tls"

class RaihaNextTLSCodecWriterTest < Minitest::Test
  Codec = Raiha::Next::TLS::Codec

  def test_integers
    w = Codec::Writer.new
    w.u8(0x01)
    w.u16(0x0203)
    w.u24(0x040506)
    w.u32(0x0708090a)
    assert_equal_bin "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a".b, w.to_s
  end

  def test_output_is_binary_with_bytes_above_0x7f
    w = Codec::Writer.new
    w.u8(0xff)
    w.u16(0x80ff)
    w.bytes("\xe3\x81\x82".b)
    assert_equal Encoding::BINARY, w.to_s.encoding
    assert_equal 6, w.to_s.bytesize
  end

  def test_bytes_given_a_non_binary_string_stay_binary
    w = Codec::Writer.new
    w.bytes("あ")
    assert_equal Encoding::BINARY, w.to_s.encoding
    assert_equal_bin "\xe3\x81\x82".b, w.to_s
  end

  def test_integer_out_of_range
    w = Codec::Writer.new
    assert_raises(Codec::EncodeError) { w.u8(0x100) }
    assert_raises(Codec::EncodeError) { w.u16(0x10000) }
    assert_raises(Codec::EncodeError) { w.u24(0x1000000) }
    assert_raises(Codec::EncodeError) { w.u32(0x100000000) }
    assert_raises(Codec::EncodeError) { w.u8(-1) }
  end

  def test_vector_fills_in_its_length
    w = Codec::Writer.new
    w.vector(1) { w.bytes("abc") }
    w.vector(2) { w.u16(0x1301) }
    w.vector(3) { w.bytes("xy") }
    assert_equal_bin "\x03abc\x00\x02\x13\x01\x00\x00\x02xy".b, w.to_s
  end

  def test_nested_vectors
    w = Codec::Writer.new
    w.vector(3) do
      w.u16(0x0303)
      w.vector(1) { w.bytes("id") }
      w.vector(2) { [0x1301, 0x1302].each { |cs| w.u16(cs) } }
    end
    assert_equal_bin "\x00\x00\x0b\x03\x03\x02id\x00\x04\x13\x01\x13\x02".b, w.to_s
  end

  def test_empty_vector
    w = Codec::Writer.new
    w.vector(2) { nil }
    assert_equal_bin "\x00\x00".b, w.to_s
  end

  def test_vector_length_overflow
    w = Codec::Writer.new
    assert_raises(Codec::EncodeError) { w.vector(1) { w.bytes("x" * 256) } }
    w = Codec::Writer.new
    w.vector(1) { w.bytes("x" * 255) }
    assert_equal 256, w.to_s.bytesize
  end

  def test_vector_bounds
    w = Codec::Writer.new
    assert_raises(Codec::EncodeError) { w.vector(2, min: 2, max: 0xfffe) { nil } }
    w = Codec::Writer.new
    assert_raises(Codec::EncodeError) { w.vector(1, min: 1, max: 2) { w.bytes("abc") } }
    w = Codec::Writer.new
    w.vector(1, min: 2, max: 2) { w.bytes("ab") }
    assert_equal_bin "\x02ab".b, w.to_s
  end

  def test_rejects_a_length_prefix_wider_than_three_bytes
    assert_raises(ArgumentError) { Codec::Writer.new.vector(4) { nil } }
  end

  def test_round_trip_through_reader
    w = Codec::Writer.new
    w.vector(2) { w.vector(1) { w.bytes("h3") } }
    r = Codec::Reader.new(w.to_s)
    names = []
    r.vector(2, max: 0xffff) { |v| names << v.opaque(1, min: 1, max: 255) until v.eof? }
    assert_equal ["h3"], names
  end
end
