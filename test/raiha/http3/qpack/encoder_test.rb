require "test_helper"
require "raiha/http3/qpack"

# The encoder refers to the static table and sends the rest as literals
# (RFC 9204 "Field Line Representations"); it never inserts into the
# dynamic table.
class RaihaNextQPACKEncoderTest < Minitest::Test
  QPACK = Raiha::Next::HTTP3::QPACK
  Huffman = QPACK::Huffman

  # RFC 9204 Appendix B.1, but with the value in the Huffman code, which is
  # shorter than the example's literal octets.
  def test_rfc9204_literal_field_line_with_name_reference
    bytes = encode(field(":path", "/index.html"))
    assert_equal "\x00\x00\x51\x88".b + Huffman.encode("/index.html".b), bytes
  end

  def test_prefix_has_no_dynamic_table_reference
    assert_equal "\x00\x00".b, encode
  end

  def test_indexed_field_line_for_a_static_entry
    assert_equal "\x00\x00\xd1".b, encode(field(":method", "GET"))   # index 17
    assert_equal "\x00\x00\xff\x23".b, encode(field("x-frame-options", "sameorigin")) # 98 = 63 + 35
  end

  def test_name_reference_for_a_static_name
    assert_equal "\x00\x00\x50\x03a.b".b, encode(field(":authority", "a.b"))
    assert_equal "\x00\x00\x5f\x1d\x01x".b, encode(field("content-type", "x")) # 44 = 15 + 29
  end

  def test_literal_name_otherwise
    assert_equal "\x00\x00\x2a".b + Huffman.encode("abc".b) + "\x01v".b, encode(field("abc", "v"))
    assert_equal "\x00\x00\x22{}\x01v".b, encode(field("{}", "v")) # longer in the Huffman code
    long = "x-custom-header"
    assert_equal "\x00\x00\x2f".b + [Huffman.encoded_length(long.b) - 7].pack("C") + Huffman.encode(long.b) + "\x01v".b,
      encode(field(long, "v"))
  end

  # RFC 9204 "Never-Indexed Literals": the N bit, and a literal even for a
  # field the static table holds.
  def test_never_indexed_is_always_a_literal
    assert_equal "\x00\x00\x7f\x00\x03GET".b, encode(field(":method", "GET", never_indexed: true))
    assert_equal "\x00\x00\x70\x03a.b".b, encode(field(":authority", "a.b", never_indexed: true))
    assert_equal "\x00\x00\x3a".b + Huffman.encode("abc".b) + "\x01v".b, encode(field("abc", "v", never_indexed: true))
  end

  def test_takes_strings_of_any_encoding
    bytes = encode(field("x-name", "café"))
    assert_equal Encoding::BINARY, bytes.encoding
    assert bytes.end_with?("café".b)
  end

  def test_fields_are_frozen_and_shareable
    value = +"text"
    field = QPACK::Field.new(name: "a", value:)
    assert field.value.frozen?
    refute value.frozen?, "the caller's String is left alone"
    refute field.never_indexed
    assert Ractor.shareable?(field)
    assert_equal QPACK::Field.new(name: "a", value: "text", never_indexed: false), field
  end

  private def field(name, value, never_indexed: false) = QPACK::Field.new(name:, value:, never_indexed:)

  private def encode(*fields) = QPACK::Encoder.new.encode(0, fields)
end
