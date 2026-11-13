require "test_helper"
require "raiha/tls"

class RaihaNextTLSCodecReaderTest < Minitest::Test
  Codec = Raiha::Next::TLS::Codec

  def test_integers
    r = Codec::Reader.new("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a".b)
    assert_equal 0x01, r.u8
    assert_equal 0x0203, r.u16
    assert_equal 0x040506, r.u24
    assert_equal 0x0708090a, r.u32
    assert r.eof?
  end

  def test_integers_use_all_eight_bits
    r = Codec::Reader.new("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff".b)
    assert_equal 0xff, r.u8
    assert_equal 0xffff, r.u16
    assert_equal 0xffffff, r.u24
    assert_equal 0xffffffff, r.u32
  end

  def test_truncated_integer
    assert_raises(Codec::Truncated) { Codec::Reader.new("".b).u8 }
    assert_raises(Codec::Truncated) { Codec::Reader.new("\x00".b).u16 }
    assert_raises(Codec::Truncated) { Codec::Reader.new("\x00\x00".b).u24 }
    assert_raises(Codec::Truncated) { Codec::Reader.new("\x00\x00\x00".b).u32 }
  end

  def test_bytes_is_a_frozen_binary_copy
    buf = "abcd".b
    bytes = Codec::Reader.new(buf).bytes(3)
    assert_equal "abc".b, bytes
    assert bytes.frozen?
    assert_equal Encoding::BINARY, bytes.encoding
    refute buf.frozen?
  end

  def test_bytes_past_the_end
    assert_raises(Codec::Truncated) { Codec::Reader.new("ab".b).bytes(3) }
  end

  def test_opaque
    r = Codec::Reader.new("\x00\x02ab".b)
    assert_equal "ab".b, r.opaque(2, max: 0xffff)
    assert r.eof?
  end

  def test_opaque_bounds
    assert_raises(Codec::RangeViolation) { Codec::Reader.new("\x00".b).opaque(1, min: 1, max: 32) }
    assert_raises(Codec::RangeViolation) { Codec::Reader.new("\x03abc".b).opaque(1, max: 2) }
    assert_equal "ab".b, Codec::Reader.new("\x02ab".b).opaque(1, min: 2, max: 2)
  end

  def test_opaque_shorter_than_its_length
    assert_raises(Codec::Truncated) { Codec::Reader.new("\x03ab".b).opaque(1, max: 255) }
  end

  def test_vector_yields_a_view_over_its_contents
    r = Codec::Reader.new("\x00\x04\x13\x01\x13\x02\xff".b)
    suites = []
    r.vector(2, min: 2, max: 0xfffe) { |v| suites << v.u16 until v.eof? }
    assert_equal [0x1301, 0x1302], suites
    assert_equal 1, r.remaining
    assert_equal 0xff, r.u8
  end

  def test_vector_returns_what_the_block_returns
    r = Codec::Reader.new("\x02ab".b)
    assert_equal "ab".b, r.vector(1, max: 255) { |v| v.bytes(2) }
  end

  def test_vector_view_cannot_read_past_its_end
    r = Codec::Reader.new("\x01\xaa\xbb".b)
    assert_raises(Codec::Truncated) { r.vector(1, max: 255) { |v| v.u16 } }
  end

  def test_vector_with_trailing_data
    r = Codec::Reader.new("\x03\x00\x01\x02".b)
    assert_raises(Codec::TrailingData) { r.vector(1, max: 255) { |v| v.u16 } }
  end

  def test_nested_vectors
    r = Codec::Reader.new("\x00\x05\x03abc\x00".b)
    inner = nil
    tail = nil
    r.vector(2, max: 0xffff) do |v|
      inner = v.opaque(1, max: 255)
      tail = v.u8
    end
    assert_equal "abc".b, inner
    assert_equal 0, tail
    assert r.eof?
  end

  def test_vector_bounds
    assert_raises(Codec::RangeViolation) { Codec::Reader.new("\x00\x00".b).vector(2, min: 2, max: 0xfffe) { nil } }
    assert_raises(Codec::RangeViolation) { Codec::Reader.new("\x00\x01\x00".b).vector(2, min: 2, max: 0xfffe) { |v| v.u8 } }
  end

  def test_vector_three_byte_length
    r = Codec::Reader.new("\x00\x00\x02ab".b)
    r.vector(3, max: 0xffffff) { |v| assert_equal "ab".b, v.bytes(2) }
    assert r.eof?
  end

  def test_finish
    r = Codec::Reader.new("\x00".b)
    assert_raises(Codec::TrailingData) { r.finish! }
    r.u8
    r.finish!
  end

  def test_starts_at_the_given_position_and_limit
    r = Codec::Reader.new("\x01\x02\x03\x04".b, 1, 3)
    assert_equal 2, r.remaining
    assert_equal 0x0203, r.u16
    assert r.eof?
    assert_raises(Codec::Truncated) { r.u8 }
  end

  def test_rejects_a_length_prefix_wider_than_three_bytes
    assert_raises(ArgumentError) { Codec::Reader.new("\x00\x00\x00\x00".b).opaque(4, max: 1) }
  end
end
