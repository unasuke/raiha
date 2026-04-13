require "test_helper"
require "raiha/quic/wire/frame_parser"

class RaihaQuicWireFrameParserTest < Minitest::Test
  def test_parse_ping_frame
    buf = Raiha::Quic::Wire::Buffer.new(Raiha::Quic::Varint.encode(0x01))
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    assert_equal 1, frames.length
    assert_instance_of Raiha::Quic::Wire::Frames::PingFrame, frames.first
  end

  def test_parse_padding_frame
    buf = Raiha::Quic::Wire::Buffer.new(Raiha::Quic::Varint.encode(0x00))
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    assert_equal 1, frames.length
    assert_instance_of Raiha::Quic::Wire::Frames::PaddingFrame, frames.first
    refute frames.first.ack_eliciting?
  end

  def test_parse_crypto_frame
    data = "hello".b
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x06) # CRYPTO
    buf.write_varint(0)    # offset
    buf.write_varint(data.bytesize)
    buf.write(data)

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    assert_equal 1, frames.length
    crypto = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::CryptoFrame, crypto
    assert_equal 0, crypto.offset
    assert_equal "hello".b, crypto.data
  end

  def test_parse_ack_frame
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x02) # ACK
    buf.write_varint(100)  # largest acknowledged
    buf.write_varint(25)   # ack delay
    buf.write_varint(0)    # ack range count
    buf.write_varint(10)   # first ack range

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    ack = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::AckFrame, ack
    assert_equal 100, ack.largest_acknowledged
    assert_equal 25, ack.ack_delay
    assert_equal 1, ack.ack_ranges.length
    refute ack.ack_eliciting?
  end

  def test_parse_stream_frame
    # 0x0e = 0x08 | 0x04 | 0x02 = STREAM with OFF + LEN
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x0e)
    buf.write_varint(4)    # stream id
    buf.write_varint(100)  # offset
    buf.write_varint(5)    # length
    buf.write("world")

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    stream = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::StreamFrame, stream
    assert_equal 4, stream.stream_id
    assert_equal 100, stream.offset
    assert_equal "world", stream.data
    refute stream.fin
  end

  def test_parse_connection_close_frame
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x1c) # CONNECTION_CLOSE
    buf.write_varint(0x0a) # error code (PROTOCOL_VIOLATION)
    buf.write_varint(0x06) # frame type (CRYPTO)
    buf.write_varint(4)    # reason phrase length
    buf.write("test")

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    cc = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::ConnectionCloseFrame, cc
    assert_equal 0x0a, cc.error_code
    assert_equal 0x06, cc.trigger_frame_type
    assert_equal "test", cc.reason_phrase
    refute cc.application_error
  end

  def test_parse_handshake_done_frame
    buf = Raiha::Quic::Wire::Buffer.new(Raiha::Quic::Varint.encode(0x1e))
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    assert_equal 1, frames.length
    assert_instance_of Raiha::Quic::Wire::Frames::HandshakeDoneFrame, frames.first
  end

  def test_parse_multiple_frames
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x01) # PING
    buf.write_varint(0x01) # PING
    buf.write_varint(0x1e) # HANDSHAKE_DONE

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    assert_equal 3, frames.length
    assert_instance_of Raiha::Quic::Wire::Frames::PingFrame, frames[0]
    assert_instance_of Raiha::Quic::Wire::Frames::PingFrame, frames[1]
    assert_instance_of Raiha::Quic::Wire::Frames::HandshakeDoneFrame, frames[2]
  end

  def test_crypto_frame_roundtrip
    original = Raiha::Quic::Wire::Frames::CryptoFrame.new
    original.offset = 42
    original.data = "TLS handshake data".b

    serialized = original.serialize
    buf = Raiha::Quic::Wire::Buffer.new(serialized)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)

    parsed = frames.first
    assert_equal 42, parsed.offset
    assert_equal "TLS handshake data".b, parsed.data
  end

  def test_stream_frame_roundtrip
    original = Raiha::Quic::Wire::Frames::StreamFrame.new
    original.stream_id = 8
    original.offset = 256
    original.data = "stream payload".b
    original.fin = true

    serialized = original.serialize
    buf = Raiha::Quic::Wire::Buffer.new(serialized)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)

    parsed = frames.first
    assert_equal 8, parsed.stream_id
    assert_equal 256, parsed.offset
    assert_equal "stream payload".b, parsed.data
    assert parsed.fin
  end

  def test_parse_reset_stream_frame
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x04) # RESET_STREAM
    buf.write_varint(4)    # stream id
    buf.write_varint(0x0c) # application error
    buf.write_varint(1024) # final size

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::ResetStreamFrame, frame
    assert_equal 4, frame.stream_id
    assert_equal 0x0c, frame.application_protocol_error_code
    assert_equal 1024, frame.final_size
  end

  def test_parse_stop_sending_frame
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x05) # STOP_SENDING
    buf.write_varint(8)    # stream id
    buf.write_varint(0x0c) # application error

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::StopSendingFrame, frame
    assert_equal 8, frame.stream_id
    assert_equal 0x0c, frame.application_protocol_error_code
  end

  def test_parse_new_token_frame
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x07)    # NEW_TOKEN
    buf.write_varint(4)       # token length
    buf.write("\xde\xad\xbe\xef".b)

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::NewTokenFrame, frame
    assert_equal "\xde\xad\xbe\xef".b, frame.token
  end

  def test_parse_max_data_frame
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x10) # MAX_DATA
    buf.write_varint(65536)

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::MaxDataFrame, frame
    assert_equal 65536, frame.maximum_data
  end

  def test_parse_max_stream_data_frame
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x11)  # MAX_STREAM_DATA
    buf.write_varint(4)     # stream id
    buf.write_varint(32768) # max stream data

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::MaxStreamDataFrame, frame
    assert_equal 4, frame.stream_id
    assert_equal 32768, frame.maximum_stream_data
  end

  def test_parse_max_streams_bidi_frame
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x12) # MAX_STREAMS_BIDI
    buf.write_varint(100)

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::MaxStreamsFrame, frame
    assert_equal 100, frame.maximum_streams
    assert frame.bidirectional
  end

  def test_parse_max_streams_uni_frame
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x13) # MAX_STREAMS_UNI
    buf.write_varint(50)

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::MaxStreamsFrame, frame
    assert_equal 50, frame.maximum_streams
    refute frame.bidirectional
  end

  def test_parse_data_blocked_frame
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x14) # DATA_BLOCKED
    buf.write_varint(4096)

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::DataBlockedFrame, frame
    assert_equal 4096, frame.maximum_data
  end

  def test_parse_stream_data_blocked_frame
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x15) # STREAM_DATA_BLOCKED
    buf.write_varint(4)    # stream id
    buf.write_varint(2048)

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::StreamDataBlockedFrame, frame
    assert_equal 4, frame.stream_id
    assert_equal 2048, frame.maximum_stream_data
  end

  def test_parse_streams_blocked_bidi_frame
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x16) # STREAMS_BLOCKED_BIDI
    buf.write_varint(10)

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::StreamsBlockedFrame, frame
    assert_equal 10, frame.maximum_streams
    assert frame.bidirectional
  end

  def test_parse_streams_blocked_uni_frame
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x17) # STREAMS_BLOCKED_UNI
    buf.write_varint(5)

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::StreamsBlockedFrame, frame
    assert_equal 5, frame.maximum_streams
    refute frame.bidirectional
  end

  def test_parse_new_connection_id_frame
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x18) # NEW_CONNECTION_ID
    buf.write_varint(1)    # sequence number
    buf.write_varint(0)    # retire prior to
    buf.write_uint8(8)     # connection id length
    buf.write("\x01\x02\x03\x04\x05\x06\x07\x08".b)
    buf.write("\x00" * 16) # stateless reset token

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::NewConnectionIdFrame, frame
    assert_equal 1, frame.sequence_number
    assert_equal 0, frame.retire_prior_to
    assert_equal 8, frame.connection_id.length
    assert_equal 16, frame.stateless_reset_token.bytesize
  end

  def test_parse_retire_connection_id_frame
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x19) # RETIRE_CONNECTION_ID
    buf.write_varint(3)

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::RetireConnectionIdFrame, frame
    assert_equal 3, frame.sequence_number
  end

  def test_parse_path_challenge_frame
    challenge_data = "\x01\x02\x03\x04\x05\x06\x07\x08".b
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x1a) # PATH_CHALLENGE
    buf.write(challenge_data)

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::PathChallengeFrame, frame
    assert_equal challenge_data, frame.data
  end

  def test_parse_path_response_frame
    response_data = "\xaa\xbb\xcc\xdd\xee\xff\x00\x11".b
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x1b) # PATH_RESPONSE
    buf.write(response_data)

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::PathResponseFrame, frame
    assert_equal response_data, frame.data
  end

  def test_parse_connection_close_app_frame
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x1d) # CONNECTION_CLOSE_APP
    buf.write_varint(42)   # application error code
    buf.write_varint(6)    # reason phrase length
    buf.write("bye!  ")

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::ConnectionCloseFrame, frame
    assert_equal 42, frame.error_code
    assert frame.application_error
    assert_nil frame.trigger_frame_type
  end

  def test_parse_ack_frame_with_ecn
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x03) # ACK_ECN
    buf.write_varint(200)  # largest acknowledged
    buf.write_varint(10)   # ack delay
    buf.write_varint(0)    # ack range count
    buf.write_varint(5)    # first ack range
    buf.write_varint(100)  # ECT(0)
    buf.write_varint(50)   # ECT(1)
    buf.write_varint(3)    # ECN-CE

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    ack = frames.first
    assert_instance_of Raiha::Quic::Wire::Frames::AckFrame, ack
    assert_equal 200, ack.largest_acknowledged
    refute_nil ack.ecn_counts
    assert_equal 100, ack.ecn_counts[:ect0]
    assert_equal 50, ack.ecn_counts[:ect1]
    assert_equal 3, ack.ecn_counts[:ecn_ce]
  end

  def test_parse_ack_frame_with_multiple_ranges
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x02) # ACK
    buf.write_varint(50)   # largest acknowledged
    buf.write_varint(0)    # ack delay
    buf.write_varint(2)    # ack range count (2 additional ranges)
    buf.write_varint(10)   # first ack range
    buf.write_varint(3)    # gap 1
    buf.write_varint(5)    # range 1
    buf.write_varint(1)    # gap 2
    buf.write_varint(2)    # range 2

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    ack = frames.first
    assert_equal 3, ack.ack_ranges.length
    assert_equal 10, ack.ack_ranges[0].ack_range_length
    assert_equal 3, ack.ack_ranges[1].gap
    assert_equal 5, ack.ack_ranges[1].ack_range_length
    assert_equal 1, ack.ack_ranges[2].gap
    assert_equal 2, ack.ack_ranges[2].ack_range_length
  end

  def test_parse_stream_frame_without_offset
    # 0x0a = 0x08 | 0x02 = STREAM with LEN, no OFF, no FIN
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x0a)
    buf.write_varint(0)    # stream id
    buf.write_varint(3)    # length
    buf.write("abc")

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert_equal 0, frame.offset
    assert_equal "abc", frame.data
    refute frame.fin
  end

  def test_parse_stream_frame_with_fin
    # 0x0f = 0x08 | 0x04 | 0x02 | 0x01 = STREAM with OFF + LEN + FIN
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x0f)
    buf.write_varint(4)    # stream id
    buf.write_varint(0)    # offset
    buf.write_varint(0)    # length

    buf.seek(0)
    frames = Raiha::Quic::Wire::FrameParser.parse(buf)
    frame = frames.first
    assert frame.fin
    assert_equal 4, frame.stream_id
  end
end
