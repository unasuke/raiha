require "test_helper"
require "raiha/http3/qpack"

# The encoder follows the decoder stream (RFC 9204 "Decoder
# Instructions"). It never refers to the dynamic table, so only a Stream
# Cancellation is in order.
class RaihaNextQPACKEncoderDecoderStreamTest < Minitest::Test
  QPACK = Raiha::Next::HTTP3::QPACK

  def setup
    @encoder = QPACK::Encoder.new
  end

  def test_stream_cancellations_are_taken
    assert_nil @encoder.receive_decoder_stream("".b)
    assert_nil @encoder.receive_decoder_stream("\x40\x44\x7f\x00".b) # streams 0, 4 and 63
  end

  def test_an_instruction_cut_short_waits_for_the_rest
    assert_nil @encoder.receive_decoder_stream("\x7f".b)
    assert_nil @encoder.receive_decoder_stream("\x80".b)
    assert_nil @encoder.receive_decoder_stream("\x01\x41".b) # 63 + 128, then 1
    assert_nil @encoder.receive_decoder_stream("\xff".b)
    failure = @encoder.receive_decoder_stream("\x05".b)
    assert_equal QPACK::ErrorCode::DECODER_STREAM_ERROR, failure.code
    assert_match(/stream 132/, failure.reason)
  end

  # RFC 9204 "Section Acknowledgment": one for a stream with no section to
  # acknowledge is a connection error.
  def test_a_section_acknowledgment_is_a_failure
    failure = @encoder.receive_decoder_stream("\x84".b)
    assert_equal QPACK::Failure.new(code: QPACK::ErrorCode::DECODER_STREAM_ERROR,
      reason: "a Section Acknowledgment for stream 4, which has no section to acknowledge"), failure
    assert_nil failure.stream_id
  end

  # RFC 9204 "Insert Count Increment": an Increment of 0, or one past the
  # entries the encoder inserted, is a connection error.
  def test_an_insert_count_increment_is_a_failure
    assert_equal QPACK::ErrorCode::DECODER_STREAM_ERROR, QPACK::Encoder.new.receive_decoder_stream("\x00".b).code
    assert_equal QPACK::ErrorCode::DECODER_STREAM_ERROR, QPACK::Encoder.new.receive_decoder_stream("\x01".b).code
  end

  def test_an_integer_past_62_bits_is_a_failure
    failure = @encoder.receive_decoder_stream("\x7f#{"\xff" * 9}\x01".b)
    assert_equal QPACK::ErrorCode::DECODER_STREAM_ERROR, failure.code
    assert_nil failure.stream_id
  end

  def test_the_failure_stays
    failure = @encoder.receive_decoder_stream("\x40\x84\x40".b)
    assert_same failure, @encoder.receive_decoder_stream("\x40".b)
  end

  def test_no_instructions_to_send
    @encoder.encode(0, [QPACK::Field.new(name: "a", value: "b")])
    assert_equal "".b, @encoder.take_instructions
  end
end
