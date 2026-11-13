require "test_helper"
require "raiha/http3/qpack"

# What the decoder writes on the decoder stream (RFC 9204 "Decoder
# Instructions"), taken with `take_instructions`.
class RaihaNextQPACKDecoderInstructionsTest < Minitest::Test
  QPACK = Raiha::Next::HTTP3::QPACK

  def setup
    @decoder = QPACK::Decoder.new(max_table_capacity: 4096, max_blocked_streams: 16)
    @decoder.receive_encoder_stream(capacity(4096))
  end

  def test_nothing_at_first
    assert_equal "".b, @decoder.take_instructions
    @decoder.decode(4, "\x00\x00\xd1".b)
    assert_equal "".b, @decoder.take_instructions, "a section with no dynamic reference is not acknowledged"
  end

  # RFC 9204 "New Table Entries": one Insert Count Increment for all the
  # entries inserted since the last.
  def test_one_insert_count_increment_for_the_entries
    @decoder.receive_encoder_stream(insert("a", "0") + insert("b", "1"))
    @decoder.receive_encoder_stream(insert("c", "2"))
    assert_equal "\x03".b, @decoder.take_instructions
    assert_equal "".b, @decoder.take_instructions
    @decoder.receive_encoder_stream(insert("d", "3"))
    assert_equal "\x01".b, @decoder.take_instructions
  end

  # RFC 9204 "Completed Processing of a Field Section": a section that
  # refers to the dynamic table is acknowledged, which also tells the
  # encoder of the entries below its Required Insert Count.
  def test_a_section_acknowledgment
    @decoder.receive_encoder_stream(insert("a", "0") + insert("b", "1") + insert("c", "2"))
    @decoder.decode(200, section(2))
    assert_equal "\xff\x49\x01".b, @decoder.take_instructions # stream 200 = 127 + 73, then 1 more entry
    @decoder.decode(4, section(3))
    assert_equal "\x84".b, @decoder.take_instructions
  end

  def test_acknowledged_once_unblocked
    @decoder.decode(8, section(1))
    assert_equal "".b, @decoder.take_instructions
    @decoder.receive_encoder_stream(insert("a", "0"))
    assert_equal "\x88".b, @decoder.take_instructions
  end

  # RFC 9204 "Abandonment of a Stream".
  def test_a_stream_cancellation
    @decoder.decode(8, section(1))
    @decoder.cancel(8)
    @decoder.cancel(70)
    assert_equal "\x48\x7f\x07".b, @decoder.take_instructions # 70 = 63 + 7
  end

  def test_no_stream_cancellation_with_no_table
    decoder = QPACK::Decoder.new
    decoder.cancel(8)
    assert_equal "".b, decoder.take_instructions
  end

  private def section(required) = QPACK::Writer.new.integer((required % 256) + 1, 8).integer(0, 7).integer(0, 6, 0x80).to_s

  private def capacity(value) = QPACK::Writer.new.integer(value, 5, 0x20).to_s

  private def insert(name, value) = QPACK::Writer.new.string(name.b, 6, 0x40).string(value.b, 8).to_s
end
