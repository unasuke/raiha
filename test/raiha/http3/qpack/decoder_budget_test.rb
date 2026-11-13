require "test_helper"
require "raiha/http3/qpack"

# The decoder counts the fields against a budget as they come out, each
# its name and value and 32 more (RFC 9114 "Header Size Constraints"),
# and stops at the line that passes it.
class RaihaNextQPACKDecoderBudgetTest < Minitest::Test
  QPACK = Raiha::Next::HTTP3::QPACK

  def test_64_kib_by_default
    assert_equal 65_536, QPACK::Decoder::DEFAULT_MAX_FIELD_SECTION_SIZE
    exact = [field("x-a", "v" * (65_536 - 35))] # 3 + 65,501 + 32
    assert_equal 65_536, QPACK::Decoder.new.decode(0, encode(exact)).size
    assert_equal QPACK::Oversized.new(stream_id: 0), QPACK::Decoder.new.decode(0, encode([field("x-a", "v" * (65_536 - 34))]))
  end

  def test_a_limit_of_the_callers
    fields = [field(":method", "GET"), field("x-a", "b")] # 42 + 36
    assert_kind_of QPACK::Decoded, QPACK::Decoder.new.decode(0, encode(fields), limit: 78)
    assert_kind_of QPACK::Oversized, QPACK::Decoder.new.decode(0, encode(fields), limit: 77)
    assert_kind_of QPACK::Oversized, QPACK::Decoder.new(max_field_section_size: 77).decode(0, encode(fields))
    assert_raises(ArgumentError) { QPACK::Decoder.new.decode(0, encode(fields), limit: -1) }
  end

  # What is left of the budget after the headers is the trailers' limit.
  def test_the_trailers_take_what_the_headers_left
    decoder = QPACK::Decoder.new(max_field_section_size: 100)
    headers = decoder.decode(0, encode([field("x-a", "b")])) # 36
    assert_kind_of QPACK::Decoded, decoder.decode(0, encode([field("x-b", "c" * 29)]), limit: 100 - headers.size) # 64
    assert_kind_of QPACK::Oversized, decoder.decode(0, encode([field("x-b", "c" * 30)]), limit: 100 - headers.size)
  end

  # Lines that take next to nothing on the wire count in full.
  def test_indexed_lines_count
    section = "\x00\x00".b + ("\xd1".b * 2_000) # :method GET, 42 each
    assert_kind_of QPACK::Oversized, QPACK::Decoder.new.decode(0, section)
  end

  # A string declared longer than the budget allows is not waited for or
  # expanded.
  def test_a_string_sure_to_pass_the_budget
    section = "\x00\x00\x5f\x0d\x7f\xff\xff\x7f".b # content-type, a value of 2^21 + 126 octets, none sent
    assert_kind_of QPACK::Oversized, QPACK::Decoder.new.decode(0, section)
    huffman = "\x00\x00\x5f\x0d\xff\xff\xff\x7f".b # in the Huffman code, still sure to pass
    assert_kind_of QPACK::Oversized, QPACK::Decoder.new.decode(0, huffman)
  end

  # RFC 9204 "Abandonment of a Stream": a section left undecoded with
  # references to the dynamic table is cancelled.
  def test_an_oversized_section_with_references_is_cancelled
    decoder = with_entry("x-a", "v" * 100)
    assert_kind_of QPACK::Oversized, decoder.decode(4, "\x02\x00\x80".b, limit: 100)
    assert_equal "\x44\x01".b, decoder.take_instructions # stream 4, then the increment
    assert_kind_of QPACK::Oversized, decoder.decode(8, encode([field("x-a", "v" * 100)]), limit: 100)
    assert_equal "".b, decoder.take_instructions, "nothing to cancel without references"
  end

  def test_an_unblocked_section_past_the_budget
    decoder = QPACK::Decoder.new(max_table_capacity: 4096, max_blocked_streams: 1)
    decoder.receive_encoder_stream(capacity(4096))
    assert_kind_of QPACK::Blocked, decoder.decode(4, "\x02\x00\x80".b, limit: 100)
    assert_equal [QPACK::Oversized.new(stream_id: 4)], decoder.receive_encoder_stream(insert("x-a", "v" * 100))
    assert_equal "\x44\x01".b, decoder.take_instructions
  end

  # A line takes at most four times its size on the wire, so a section
  # longer than that cannot fit the budget and is not kept to wait.
  def test_a_section_too_long_to_fit_is_not_kept_blocked
    decoder = QPACK::Decoder.new(max_table_capacity: 4096, max_blocked_streams: 1)
    decoder.receive_encoder_stream(capacity(4096))
    long = "\x02\x00".b + ("\x80".b * 401)
    assert_kind_of QPACK::Oversized, decoder.decode(4, long, limit: 100)
    assert_equal "\x44".b, decoder.take_instructions
    assert_kind_of QPACK::Blocked, decoder.decode(8, "\x02\x00".b + ("\x80".b * 400), limit: 100), "its place is still free"
  end

  private def field(name, value) = QPACK::Field.new(name: name.b, value: value.b)

  private def encode(fields) = QPACK::Encoder.new.encode(0, fields)

  private def with_entry(name, value)
    QPACK::Decoder.new(max_table_capacity: 4096).tap { _1.receive_encoder_stream(capacity(4096) + insert(name, value)) }
  end

  private def capacity(value) = QPACK::Writer.new.integer(value, 5, 0x20).to_s

  private def insert(name, value) = QPACK::Writer.new.string(name.b, 6, 0x40).string(value.b, 8).to_s
end
