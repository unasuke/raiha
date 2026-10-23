require "raiha/next/test_helper"
require "raiha/next/http3/qpack"

# RFC 9204 "String Literals": the string of RFC 7541, which may start
# mid-byte after an N-bit prefix.
class RaihaNextQPACKStringLiteralTest < Minitest::Test
  QPACK = Raiha::Next::HTTP3::QPACK

  # RFC 7541 Appendix C.4.1 and C.3.1.
  def test_rfc7541_examples
    huffman = ["8cf1e3c2e5f23a6ba0ab90f4ff"].pack("H*")
    plain = "\x0fwww.example.com".b
    assert_equal huffman, QPACK::Writer.new.string("www.example.com".b, 8).to_s
    assert_equal "www.example.com", QPACK::Reader.new(huffman).string(8)
    assert_equal "www.example.com", QPACK::Reader.new(plain).string(8)
  end

  def test_writes_huffman_only_when_shorter
    assert_equal "\x02\x00\x01".b, QPACK::Writer.new.string("\x00\x01".b, 8).to_s
    assert_equal "\x00".b, QPACK::Writer.new.string("".b, 8).to_s
  end

  def test_round_trip_after_every_prefix
    random = Random.new(9204)
    values = ["".b, "a".b, "custom-value".b, "\x00\xff".b, "x".b * 300, random.bytes(1000)]
    (2..8).each do |prefix|
      flags = (0xff << prefix) & 0xff
      values.each do |value|
        bytes = QPACK::Writer.new.string(value, prefix, flags).to_s
        assert_equal flags, bytes.getbyte(0) & flags, "the bits above a #{prefix}-bit prefix"
        reader = QPACK::Reader.new(bytes + "rest".b)
        assert_equal value, reader.string(prefix)
        assert_equal bytes.bytesize, reader.offset
      end
    end
  end

  def test_strings_come_out_frozen_and_binary
    [QPACK::Writer.new.string("value".b, 8).to_s, "\x05value".b].each do |bytes|
      string = QPACK::Reader.new(bytes).string(8)
      assert string.frozen?
      assert_equal Encoding::BINARY, string.encoding
    end
    assert_equal Encoding::BINARY, QPACK::Writer.new.string("café", 8).to_s.encoding
  end

  def test_truncated
    assert_raises(QPACK::Truncated) { QPACK::Reader.new("".b).string(8) }
    assert_raises(QPACK::Truncated) { QPACK::Reader.new("\x05val".b).string(8) }
    assert_raises(QPACK::Truncated) { QPACK::Reader.new("\x7f\xff\xff\x03".b).string(8) }
  end

  # A declared length past `max` is refused without waiting for the bytes
  # it declares.
  def test_too_long_before_the_bytes_come
    assert_raises(QPACK::TooLong) { QPACK::Reader.new("\x7f\xff\xff\x03".b).string(8, 4096) }
    assert_raises(QPACK::TooLong) { QPACK::Reader.new("\x05value".b).string(8, 4) }
    assert_equal "value", QPACK::Reader.new("\x05value".b).string(8, 5)
  end

  # Huffman octets decode to at least one octet per 30 bits; past that
  # bound the string is refused at once, and otherwise once decoded.
  def test_too_long_in_huffman
    encoded = QPACK::Writer.new.string("a".b * 100, 8).to_s
    assert_raises(QPACK::TooLong) { QPACK::Reader.new(encoded).string(8, 99) }
    assert_equal "a" * 100, QPACK::Reader.new(encoded).string(8, 100)
    huge = "\xff\xff\xff\x7f".b # H, then a length of 2^21 - 1 with nothing after it
    assert_raises(QPACK::TooLong) { QPACK::Reader.new(huge).string(8, 65_536) }
    assert_raises(QPACK::Truncated) { QPACK::Reader.new(huge).string(8, 600_000) }
  end

  def test_huffman_errors_are_malformed
    assert_raises(QPACK::Malformed) { QPACK::Reader.new("\x81\xfe".b).string(8) }
  end
end
