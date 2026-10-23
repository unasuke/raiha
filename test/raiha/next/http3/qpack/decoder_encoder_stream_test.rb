require "raiha/next/test_helper"
require "raiha/next/http3/qpack"

# The decoder follows the encoder stream (RFC 9204 "Encoder
# Instructions"). What each instruction inserts is checked by decoding
# references to it; here, which instructions are taken and which fail.
class RaihaNextQPACKDecoderEncoderStreamTest < Minitest::Test
  QPACK = Raiha::Next::HTTP3::QPACK
  ENCODER_STREAM_ERROR = QPACK::ErrorCode::ENCODER_STREAM_ERROR

  def setup
    @decoder = QPACK::Decoder.new(max_table_capacity: 4096)
  end

  def test_takes_each_instruction
    bytes = capacity(4096) + insert_literal("custom-key", "custom-value") + insert_static(0, "www.example.com") +
      insert_dynamic(0, "other.example.com") + duplicate(2)
    assert_equal [], @decoder.receive_encoder_stream(bytes)
  end

  # RFC 9204 "Set Dynamic Table Capacity": past SETTINGS_QPACK_MAX_TABLE_CAPACITY
  # is a connection error.
  def test_a_capacity_past_the_maximum
    assert_equal ENCODER_STREAM_ERROR, @decoder.receive_encoder_stream(capacity(4097)).code
    assert_equal ENCODER_STREAM_ERROR, QPACK::Decoder.new.receive_encoder_stream(capacity(1)).code
    assert_equal [], QPACK::Decoder.new.receive_encoder_stream(capacity(0))
  end

  # RFC 9204 "Dynamic Table Capacity and Eviction": an entry larger than
  # the capacity is a connection error.
  def test_an_entry_larger_than_the_capacity
    assert_equal ENCODER_STREAM_ERROR, @decoder.receive_encoder_stream(insert_literal("a", "b")).code
    decoder = QPACK::Decoder.new(max_table_capacity: 4096)
    decoder.receive_encoder_stream(capacity(64))
    assert_equal [], decoder.receive_encoder_stream(insert_literal("a", "x" * 31))
    assert_equal ENCODER_STREAM_ERROR, decoder.receive_encoder_stream(insert_literal("a", "x" * 32)).code
  end

  # The length tells the entry would not fit before its bytes come.
  def test_refuses_a_string_too_long_from_its_length
    @decoder.receive_encoder_stream(capacity(4096))
    failure = @decoder.receive_encoder_stream("\x5f\xff\xff\x03".b) # a literal name of 65,598 octets, none of them sent
    assert_equal ENCODER_STREAM_ERROR, failure.code
    assert_match(/allowed/, failure.reason)
  end

  # RFC 9204 "Static Table" and "Invalid References": an index past
  # either table is a connection error.
  def test_invalid_references
    assert_equal ENCODER_STREAM_ERROR, fresh.receive_encoder_stream(insert_static(99, "v")).code
    assert_equal ENCODER_STREAM_ERROR, fresh.receive_encoder_stream(insert_dynamic(0, "v")).code
    assert_equal ENCODER_STREAM_ERROR, fresh.receive_encoder_stream(duplicate(0)).code
    decoder = fresh
    decoder.receive_encoder_stream(insert_literal("a", "b"))
    assert_equal [], decoder.receive_encoder_stream(duplicate(0))
    assert_equal ENCODER_STREAM_ERROR, decoder.receive_encoder_stream(duplicate(2)).code
  end

  def test_a_reference_to_an_evicted_entry
    decoder = QPACK::Decoder.new(max_table_capacity: 4096)
    decoder.receive_encoder_stream(capacity(70) + insert_literal("a", "1") + insert_literal("b", "2")) # 34 each
    decoder.receive_encoder_stream(insert_literal("c", "3")) # evicts "a"
    assert_equal [], decoder.receive_encoder_stream(duplicate(1))
    assert_equal ENCODER_STREAM_ERROR, decoder.receive_encoder_stream(duplicate(2)).code
  end

  # RFC 9204 "Dynamic Table Capacity and Eviction": a new entry may refer
  # to one its insertion evicts.
  def test_an_insertion_may_refer_to_the_entry_it_evicts
    decoder = QPACK::Decoder.new(max_table_capacity: 4096)
    decoder.receive_encoder_stream(capacity(40) + insert_literal("a", "1"))
    assert_equal [], decoder.receive_encoder_stream(duplicate(0))
    assert_equal [], decoder.receive_encoder_stream(insert_dynamic(0, "2"))
  end

  def test_instructions_cut_anywhere
    bytes = capacity(4096) + insert_literal("custom-key", "custom-value") + insert_static(0, "x" * 300) + duplicate(1)
    bytes.each_byte.each_slice(3) { |slice| assert_equal [], @decoder.receive_encoder_stream(slice.pack("C*")) }
  end

  # A long value a byte at a time is not read over again for each byte.
  def test_a_long_value_a_byte_at_a_time
    decoder = QPACK::Decoder.new(max_table_capacity: 65_536)
    decoder.receive_encoder_stream(capacity(65_536))
    bytes = insert_literal("a", "x" * 60_000)
    bytes.each_byte { |byte| assert_equal [], decoder.receive_encoder_stream(byte.chr) }
  end

  def test_an_integer_past_62_bits
    assert_equal ENCODER_STREAM_ERROR, @decoder.receive_encoder_stream("\x3f#{"\xff" * 9}\x01".b).code
  end

  def test_the_failure_stays
    failure = @decoder.receive_encoder_stream(capacity(5000))
    assert_same failure, @decoder.receive_encoder_stream(capacity(10))
  end

  private def fresh = QPACK::Decoder.new(max_table_capacity: 4096).tap { _1.receive_encoder_stream(capacity(4096)) }

  private def capacity(value) = QPACK::Writer.new.integer(value, 5, 0x20).to_s

  private def insert_literal(name, value) = QPACK::Writer.new.string(name.b, 6, 0x40).string(value.b, 8).to_s

  private def insert_static(index, value) = QPACK::Writer.new.integer(index, 6, 0xc0).string(value.b, 8).to_s

  private def insert_dynamic(index, value) = QPACK::Writer.new.integer(index, 6, 0x80).string(value.b, 8).to_s

  private def duplicate(index) = QPACK::Writer.new.integer(index, 5).to_s
end
