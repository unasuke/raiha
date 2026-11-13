require "test_helper"
require "raiha/http3/qpack"

# A field section that refers to entries yet to come waits for them (RFC
# 9204 "Blocked Decoding"), as many at once as SETTINGS_QPACK_BLOCKED_STREAMS
# allows.
class RaihaNextQPACKDecoderBlockingTest < Minitest::Test
  QPACK = Raiha::Next::HTTP3::QPACK
  DECOMPRESSION_FAILED = QPACK::ErrorCode::DECOMPRESSION_FAILED

  def setup
    @decoder = QPACK::Decoder.new(max_table_capacity: 4096, max_blocked_streams: 2)
    assert_equal [], @decoder.receive_encoder_stream(capacity(4096))
  end

  def test_decoded_once_the_entries_come
    assert_equal QPACK::Blocked.new(stream_id: 4), @decoder.decode(4, section(2))
    assert_equal [], @decoder.receive_encoder_stream(insert("a", "0"))
    results = @decoder.receive_encoder_stream(insert("b", "1"))
    assert_equal [QPACK::Decoded.new(stream_id: 4, fields: [field("b", "1")], size: 34)], results
    assert_equal [field("a", "0")], @decoder.decode(4, section(1)).fields, "the stream takes another section"
  end

  def test_unblocked_by_an_instruction_completed_later
    @decoder.decode(4, section(1))
    bytes = insert("a", "0")
    assert_equal [], @decoder.receive_encoder_stream(bytes.byteslice(0, 2))
    assert_equal [4], @decoder.receive_encoder_stream(bytes.byteslice(2..)).map(&:stream_id)
  end

  def test_in_the_order_they_blocked_and_only_those_ready
    @decoder.decode(8, section(2))
    @decoder.decode(4, section(1))
    assert_equal [4], @decoder.receive_encoder_stream(insert("a", "0")).map(&:stream_id)
    assert_equal [8], @decoder.receive_encoder_stream(insert("b", "1")).map(&:stream_id)
    decoder = QPACK::Decoder.new(max_table_capacity: 4096, max_blocked_streams: 2)
    decoder.receive_encoder_stream(capacity(4096))
    decoder.decode(8, section(2))
    decoder.decode(4, section(1))
    assert_equal [8, 4], decoder.receive_encoder_stream(insert("a", "0") + insert("b", "1")).map(&:stream_id)
  end

  # RFC 9204 "Blocked Streams": more blocked streams than promised is a
  # connection error.
  def test_more_blocked_streams_than_allowed
    @decoder.decode(0, section(1))
    @decoder.decode(4, section(1))
    failure = @decoder.decode(8, section(1))
    assert_equal QPACK::ErrorCode::DECOMPRESSION_FAILED, failure.code
    assert_nil failure.stream_id
    assert_match(/past the 2 allowed/, failure.reason)
    assert_equal DECOMPRESSION_FAILED, QPACK::Decoder.new(max_table_capacity: 4096).decode(0, section(1)).code
  end

  def test_a_stream_unblocked_frees_its_place
    @decoder.decode(0, section(1))
    @decoder.decode(4, section(1))
    @decoder.receive_encoder_stream(insert("a", "0"))
    assert_kind_of QPACK::Blocked, @decoder.decode(8, section(2))
  end

  def test_a_cancelled_stream_is_forgotten
    @decoder.decode(0, section(1))
    @decoder.decode(4, section(1))
    assert_nil @decoder.cancel(4)
    assert_kind_of QPACK::Blocked, @decoder.decode(8, section(1))
    assert_equal [0, 8], @decoder.receive_encoder_stream(insert("a", "0")).map(&:stream_id)
    assert_nil @decoder.cancel(12)
  end

  def test_another_section_for_a_stream_still_blocked_is_misuse
    @decoder.decode(4, section(1))
    assert_raises(QPACK::Error::Usage) { @decoder.decode(4, section(1)) }
  end

  def test_the_bytes_are_kept_as_they_were
    bytes = +section(1)
    @decoder.decode(4, bytes)
    bytes.replace("\x00".b * bytes.bytesize)
    assert_equal [field("a", "0")], @decoder.receive_encoder_stream(insert("a", "0")).first.fields
  end

  # A section that unblocks and then does not decode fails the connection
  # for what it is, not for the encoder stream that unblocked it.
  def test_an_unblocked_section_that_does_not_decode
    @decoder.decode(4, prefix(1) + "\xff\x24".b) # static entry 99
    failure = @decoder.receive_encoder_stream(insert("a", "0"))
    assert_equal QPACK::Failure.new(code: DECOMPRESSION_FAILED, reason: "no static entry 99"), failure
    assert_same failure, @decoder.decode(8, "\x00\x00\xd1".b)
  end

  def test_an_unblocked_section_that_fails_its_stream_alone
    @decoder.decode(4, prefix(1) + "\x5f#{"\xff" * 8}\x7f".b)
    @decoder.decode(8, section(1))
    results = @decoder.receive_encoder_stream(insert("a", "0"))
    assert_equal [QPACK::Failure.new(code: DECOMPRESSION_FAILED, reason: "an integer above 2^62 - 1", stream_id: 4), 8],
      [results.first, results.last.stream_id]
  end

  private def field(name, value) = QPACK::Field.new(name: name.b, value: value.b)

  # A section of one line, the entry inserted `required`th, with the
  # Base at the Required Insert Count.
  private def section(required) = prefix(required) + [0b1000_0000].pack("C")

  private def prefix(required) = QPACK::Writer.new.integer((required % 256) + 1, 8).integer(0, 7).to_s

  private def capacity(value) = QPACK::Writer.new.integer(value, 5, 0x20).to_s

  private def insert(name, value) = QPACK::Writer.new.string(name.b, 6, 0x40).string(value.b, 8).to_s
end
