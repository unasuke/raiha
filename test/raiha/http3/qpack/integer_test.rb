require "test_helper"
require "raiha/http3/qpack"

# RFC 7541 "Integer Representation", with the limits of RFC 9204
# "Prefixed Integers" and "Implementation Limits".
class RaihaNextQPACKIntegerTest < Minitest::Test
  QPACK = Raiha::Next::HTTP3::QPACK

  # RFC 7541 Appendix C.1.
  def test_rfc7541_examples
    assert_equal "\x0a".b, encode(10, 5)
    assert_equal "\x1f\x9a\x0a".b, encode(1337, 5)
    assert_equal "\x2a".b, encode(42, 8)
    assert_equal 1337, decode("\x1f\x9a\x0a".b, 5)
  end

  def test_flags_take_the_bits_above_the_prefix
    assert_equal "\x3f\xe1\x1f".b, encode(4096, 5, 0x20)
    assert_equal 4096, decode("\x3f\xe1\x1f".b, 5)
  end

  def test_round_trip_at_every_prefix
    values = [0, 1, 2, 126, 127, 128, 254, 255, 256, 16_383, 2**32, QPACK::Reader::MAX_INTEGER]
    (1..8).each do |prefix|
      values.each do |value|
        assert_equal value, decode(encode(value, prefix), prefix), "#{value} with a #{prefix}-bit prefix"
      end
    end
  end

  def test_reads_up_to_where_the_integer_ends
    reader = QPACK::Reader.new("\x1f\x9a\x0a\x2a".b)
    assert_equal 1337, reader.integer(5)
    assert_equal 3, reader.offset
    assert_equal 42, reader.integer(8)
    assert reader.eof?
  end

  def test_truncated
    assert_raises(QPACK::Truncated) { decode("".b, 5) }
    assert_raises(QPACK::Truncated) { decode("\x1f\x9a".b, 5) }
    assert_raises(QPACK::Truncated) { QPACK::Reader.new("\x1f\x9a\x0a".b, 0, 2).integer(5) }
  end

  def test_refuses_integers_above_62_bits
    assert_raises(QPACK::IntegerOverflow) { decode(encode_unchecked(QPACK::Reader::MAX_INTEGER + 1, 5), 5) }
    assert_raises(ArgumentError) { encode(QPACK::Reader::MAX_INTEGER + 1, 5) }
    assert_raises(ArgumentError) { encode(-1, 5) }
  end

  # Zero padding past nine continuation bytes is refused, whatever the
  # value, so a peer cannot make the decoder read an integer forever.
  def test_refuses_more_than_nine_continuation_bytes
    assert_equal 31, decode("\x1f#{"\x80" * 8}\x00".b, 5)
    assert_raises(QPACK::IntegerOverflow) { decode("\x1f#{"\x80" * 9}\x00".b, 5) }
    assert_raises(QPACK::IntegerOverflow) { decode("\x1f#{"\xff" * 100}".b, 5) }
  end

  private def encode(value, prefix, flags = 0) = QPACK::Writer.new.integer(value, prefix, flags).to_s

  private def decode(bytes, prefix) = QPACK::Reader.new(bytes).integer(prefix)

  # The encoding RFC 7541 gives any value, past the limit or not.
  private def encode_unchecked(value, prefix)
    mask = (1 << prefix) - 1
    bytes = [mask]
    value -= mask
    while value >= 0x80
      bytes << ((value & 0x7f) | 0x80)
      value >>= 7
    end
    (bytes << value).pack("C*")
  end
end
