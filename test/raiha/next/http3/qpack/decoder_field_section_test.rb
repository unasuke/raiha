require "raiha/next/test_helper"
require "raiha/next/http3/qpack"

# The decoder decodes field sections (RFC 9204 "Field Line
# Representations") against the static table and the dynamic table the
# encoder stream fills.
class RaihaNextQPACKDecoderFieldSectionTest < Minitest::Test
  QPACK = Raiha::Next::HTTP3::QPACK
  DECOMPRESSION_FAILED = QPACK::ErrorCode::DECOMPRESSION_FAILED

  def test_decodes_what_the_encoder_writes
    fields = [field(":method", "GET"), field(":path", "/index.html"), field(":authority", "example.com"),
      field("x-custom", ""), field("cookie", "secret", never_indexed: true), field("x-secret", "v", never_indexed: true),
      field("accept", "*/*"), field("user-agent", "x" * 500)]
    decoded = QPACK::Decoder.new.decode(4, QPACK::Encoder.new.encode(4, fields))
    assert_equal QPACK::Decoded.new(stream_id: 4, fields:, size: fields.sum { _1.name.bytesize + _1.value.bytesize + 32 }), decoded
  end

  # RFC 9204 Appendix B.1.
  def test_rfc9204_literal_field_line_with_name_reference
    decoded = QPACK::Decoder.new.decode(0, ["0000510b2f696e6465782e68746d6c"].pack("H*"))
    assert_equal [field(":path", "/index.html")], decoded.fields
    assert_equal 48, decoded.size
  end

  def test_fields_are_frozen_and_binary
    decoded = QPACK::Decoder.new.decode(0, QPACK::Encoder.new.encode(0, [field("x-name", "value"), field(":method", "GET")]))
    decoded.fields.each do |field|
      [field.name, field.value].each do |string|
        assert string.frozen?
        assert_equal Encoding::BINARY, string.encoding
      end
    end
    assert Ractor.shareable?(decoded)
  end

  # References below the Base count back from it, post-Base ones forward
  # from it (RFC 9204 "Relative Indexing" and "Post-Base Indexing").
  def test_references_to_the_dynamic_table
    decoder = with_entries(%w[a 0], %w[b 1], %w[c 2], %w[d 3])
    section = prefix(4, 1) + # Base 2: a and b below it, c and d past it
      [0b1000_0001].pack("C") + # relative 1: a
      [0b0100_0000].pack("C") + string("x") + # name of relative 0, b
      [0b0001_0001].pack("C") + # post-Base 1: d
      [0b0000_1000].pack("C") + string("y") # never indexed, name of post-Base 0, c
    decoded = decoder.decode(0, section)
    assert_equal [field("a", "0"), field("b", "x"), field("d", "3"), field("c", "y", never_indexed: true)], decoded.fields
  end

  def test_dynamic_entries_are_not_copied
    decoder = with_entries(%w[name value])
    first, second = 2.times.map { decoder.decode(0, prefix(1, 0, base: 1) + [0b1000_0000].pack("C")).fields.first }
    assert_same first.value, second.value
  end

  # RFC 9204 "Required Insert Count": with 100 octets, the count is
  # encoded modulo 6, and after 10 insertions 4 means 9.
  def test_the_required_insert_count_wraps
    decoder = QPACK::Decoder.new(max_table_capacity: 100)
    decoder.receive_encoder_stream(capacity(100) + 10.times.map { |index| insert("n#{index}", "v") }.join)
    section = "\x04\x00".b + [0b1000_0000].pack("C") # Base 9, relative 0: entry 8
    assert_equal [field("n8", "v")], decoder.decode(0, section).fields
  end

  def test_required_insert_counts_no_encoder_sends
    decoder = QPACK::Decoder.new(max_table_capacity: 100) # 3 entries, encoded modulo 6
    assert_failure decoder.decode(0, "\x07\x00".b), /past 6/
    assert_failure QPACK::Decoder.new(max_table_capacity: 100).decode(0, "\x01\x00".b), /0 encoded/
    assert_failure QPACK::Decoder.new.decode(0, "\x01\x00".b), /past 0/
    wrapped = QPACK::Decoder.new(max_table_capacity: 100)
    wrapped.receive_encoder_stream(capacity(100) + insert("a", "b"))
    assert_failure wrapped.decode(0, "\x06\x00".b), /no encoder could send/ # 5 with one inserted
  end

  def test_a_base_below_zero
    decoder = with_entries(%w[a 0])
    assert_failure decoder.decode(0, "\x02\x81".b), /Base below 0/ # Required Insert Count 1, Base 1 - 1 - 1
  end

  # RFC 9204 "Invalid References" and "Static Table".
  def test_invalid_references
    assert_failure QPACK::Decoder.new.decode(0, "\x00\x00\xff\x24".b), /no static entry 99/
    assert_failure with_entries(%w[a 0]).decode(0, prefix(1, 0, base: 1) + "\x81".b), /dynamic entry -1/
    assert_failure with_entries(%w[a 0], %w[b 1]).decode(0, prefix(1, 0, base: 1) + "\x10".b), /not below/ # post-Base 0 is entry 1
    decoder = QPACK::Decoder.new(max_table_capacity: 4096)
    decoder.receive_encoder_stream(capacity(68) + insert("a", "1") + insert("b", "2") + insert("c", "3"))
    assert_failure decoder.decode(0, prefix(3, 0, base: 3) + "\x82".b), /evicted/
  end

  def test_bytes_that_do_not_decode
    assert_failure QPACK::Decoder.new.decode(0, "\x00\x00\x51\x85\xff\xff\xff\xff\xff".b), /Huffman/
    assert_failure QPACK::Decoder.new.decode(0, "\x00\x00\x51\x0b/index".b), /bytes wanted/
    assert_failure QPACK::Decoder.new.decode(0, "\x00".b), /byte wanted/
  end

  # Blocking comes in its own change; until then a section that refers to
  # entries yet to come fails.
  def test_a_reference_to_entries_yet_to_come
    assert_failure with_entries.decode(0, prefix(1, 0)), /yet to come/
  end

  # RFC 9204 "Implementation Limits": an integer too large to decode is an
  # error of the stream alone.
  def test_an_integer_past_62_bits_fails_the_stream_alone
    decoder = QPACK::Decoder.new
    failure = decoder.decode(8, "\x00\x00\x5f#{"\xff" * 8}\x7f".b)
    assert_equal QPACK::Failure.new(code: DECOMPRESSION_FAILED, reason: "an integer above 2^62 - 1", stream_id: 8), failure
    assert_equal [field(":method", "GET")], decoder.decode(12, "\x00\x00\xd1".b).fields
  end

  def test_the_failure_stays
    decoder = QPACK::Decoder.new
    failure = decoder.decode(0, "\x00\x00\xff\x24".b)
    assert_same failure, decoder.decode(4, "\x00\x00\xd1".b)
    assert_same failure, decoder.receive_encoder_stream("".b)
  end

  private def field(name, value, never_indexed: false) = QPACK::Field.new(name: name.b, value: value.b, never_indexed:)

  private def assert_failure(result, reason)
    assert_kind_of QPACK::Failure, result
    assert_equal DECOMPRESSION_FAILED, result.code
    assert_nil result.stream_id
    assert_match reason, result.reason
  end

  # A decoder whose dynamic table holds `entries`, with 4096 octets.
  private def with_entries(*entries)
    QPACK::Decoder.new(max_table_capacity: 4096).tap do |decoder|
      assert_equal [], decoder.receive_encoder_stream(capacity(4096) + entries.map { insert(*_1) }.join)
    end
  end

  # The prefix of a section with Required Insert Count `required` and the
  # Base `required - 1 - delta` below it, or `base` at or above it, with
  # 4096 octets (128 entries).
  private def prefix(required, delta, base: nil)
    encoded = required.zero? ? 0 : (required % 256) + 1
    writer = QPACK::Writer.new.integer(encoded, 8)
    base ? writer.integer(base - required, 7) : writer.integer(delta, 7, 0x80)
    writer.to_s
  end

  private def string(value) = QPACK::Writer.new.string(value.b, 8).to_s

  private def capacity(value) = QPACK::Writer.new.integer(value, 5, 0x20).to_s

  private def insert(name, value) = QPACK::Writer.new.string(name.b, 6, 0x40).string(value.b, 8).to_s
end
