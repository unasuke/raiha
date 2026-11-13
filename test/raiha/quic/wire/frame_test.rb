require "test_helper"
require "raiha/quic"
require "raiha/quic/test"

class RaihaNextQUICWireFrameTest < Minitest::Test
  Wire = Raiha::Next::QUIC::Wire
  Frame = Wire::Frame
  ErrorCode = Raiha::Next::QUIC::ErrorCode

  def parse(bytes, packet_type: :one_rtt) = Frame.parse(bytes.b, packet_type:, ack_delay_exponent: 3)

  def encode(*frames) = Frame.encode(frames, ack_delay_exponent: 3)

  def assert_round_trip(*frames)
    assert_equal frames, parse(encode(*frames))
  end

  def assert_malformed(bytes, code, frame_type)
    error = assert_raises(Wire::Malformed) { parse(bytes) }
    assert_equal [code, frame_type], [error.code, error.frame_type], error.message
  end

  def test_padding_ping_handshake_done
    assert_equal_bin "\x01\x00\x00\x00\x1e".b, encode(Frame::Ping.new, Frame::Padding.new(length: 3), Frame::HandshakeDone.new)
    assert_round_trip(Frame::Ping.new, Frame::Padding.new(length: 3), Frame::HandshakeDone.new)
    # A run of zero bytes is one value, to the end of the payload.
    assert_equal [Frame::Padding.new(length: 1000)], parse("\0" * 1000)
    assert_raises(ArgumentError) { Frame::Padding.new(length: 0) }
  end

  # Largest 10, ACK Delay 100, two ranges: 8..10, then a gap of one and
  # 2..5.
  ACK_BYTES = "\x02\x0a\x40\x64\x01\x02\x01\x03".b

  def ack = Frame::Ack.new(ranges: [8..10, 2..5], delay: 0.0008)

  def test_ack
    assert_equal [ack], parse(ACK_BYTES)
    assert_equal_bin ACK_BYTES, encode(ack)
    assert_equal 10, ack.largest
    assert_round_trip(Frame::Ack.new(ranges: [0..0], delay: 0.0))
    assert_round_trip(Frame::Ack.new(ranges: [100..200, 50..98, 0..0], delay: 0.025))
  end

  # ACK Delay is scaled by the exponent of the end that sent the frame.
  def test_ack_delay_exponent
    assert_equal 0.0001, Frame.parse(ACK_BYTES, packet_type: :one_rtt, ack_delay_exponent: 0).first.delay
    assert_equal 104.8576, Frame.parse(ACK_BYTES, packet_type: :one_rtt, ack_delay_exponent: 20).first.delay
    assert_equal_bin "\x02\x0a\x19\x00\x00".b, Frame.encode([Frame::Ack.new(ranges: [10..10], delay: 0.0001)], ack_delay_exponent: 2)
    # Whole microseconds, so 29 microseconds stay 29.
    assert_equal_bin "\x02\x00\x1d\x00\x00".b, Frame.encode([Frame::Ack.new(ranges: [0..0], delay: 0.000029)], ack_delay_exponent: 0)
  end

  def test_ack_ecn
    with_ecn = ack.with(ecn: Frame::Ack::ECNCounts.new(ect0: 5, ect1: 0, ce: 1))
    assert_equal_bin "\x03".b + ACK_BYTES.byteslice(1..) + "\x05\x00\x01".b, encode(with_ecn)
    assert_round_trip(with_ecn)
  end

  # The Range Count field says 64 or 2^62 - 1 ranges; one is there.
  def test_ack_range_count_is_not_trusted
    assert_malformed("\x02\x0a\x00\x40\x40\x02\x01\x03", ErrorCode::FRAME_ENCODING_ERROR, 0x02)
    assert_malformed("\x02\x0a\x00\xff\xff\xff\xff\xff\xff\xff\xff\x02\x01\x03", ErrorCode::FRAME_ENCODING_ERROR, 0x02)
  end

  # RFC 9000 "ACK Ranges": a computed packet number below 0.
  def test_ack_range_below_zero
    assert_malformed("\x02\x05\x00\x00\x06", ErrorCode::FRAME_ENCODING_ERROR, 0x02)
    assert_malformed("\x02\x05\x00\x01\x00\x04\x00", ErrorCode::FRAME_ENCODING_ERROR, 0x02)
    assert_malformed("\x02\x05\x00\x01\x00\x03\x01", ErrorCode::FRAME_ENCODING_ERROR, 0x02)
    assert_equal [Frame::Ack.new(ranges: [5..5, 0..0], delay: 0.0)], parse("\x02\x05\x00\x01\x00\x03\x00")
  end

  def test_ack_misuse
    assert_raises(ArgumentError) { Frame::Ack.new(ranges: [], delay: 0.0) }
    assert_raises(ArgumentError) { Frame::Ack.new(ranges: [2..5, 8..10], delay: 0.0) }
    assert_raises(ArgumentError) { Frame::Ack.new(ranges: [5..6, 3..4], delay: 0.0) }
    assert_raises(ArgumentError) { Frame::Ack.new(ranges: [5..3], delay: 0.0) }
    assert_raises(ArgumentError) { Frame::Ack.new(ranges: [-1..3], delay: 0.0) }
    assert_raises(ArgumentError) { Frame::Ack.new(ranges: [1..3], delay: -0.1) }
  end

  # RFC 9001 appendix A.2: the client's first CRYPTO frame, with the
  # ClientHello, then PADDING to the end of the payload.
  def test_crypto_in_the_client_initial
    c = Raiha::Next::QUIC::Test::Vectors::ClientInitial
    crypto = parse(c::FRAMES).first
    assert_equal [0, 241], [crypto.offset, crypto.data.bytesize]
    assert_equal 0x01, crypto.data.getbyte(0)
    assert_equal_bin c::FRAMES, encode(crypto)
    payload = c::FRAMES.ljust(c::PAYLOAD_LENGTH, "\0".b)
    assert_equal [crypto, Frame::Padding.new(length: c::PAYLOAD_LENGTH - c::FRAMES.bytesize)], parse(payload)
  end

  # RFC 9000 "CRYPTO Frames": data may not end past 2^62 - 1.
  def test_crypto_limits
    max = Wire::Varint::MAX
    assert_round_trip(Frame::Crypto.new(offset: max - 1, data: "x".b))
    assert_malformed("\x06\xff\xff\xff\xff\xff\xff\xff\xff\x01x", ErrorCode::FRAME_ENCODING_ERROR, 0x06)
    assert_malformed("\x06\x00\x05abc", ErrorCode::FRAME_ENCODING_ERROR, 0x06)
    assert_raises(ArgumentError) { Frame::Crypto.new(offset: max, data: "x".b) }
  end

  def test_new_token
    assert_equal_bin "\x07\x03tok".b, encode(Frame::NewToken.new(token: "tok".b))
    assert_round_trip(Frame::NewToken.new(token: "tok".b))
    # RFC 9000 "NEW_TOKEN Frames": an empty token.
    assert_malformed("\x07\x00", ErrorCode::FRAME_ENCODING_ERROR, 0x07)
    assert_raises(ArgumentError) { Frame::NewToken.new(token: "".b) }
  end

  def test_stream
    assert_equal_bin "\x0a\x04\x02hi".b, encode(Frame::Stream.new(stream_id: 4, offset: 0, data: "hi".b))
    assert_equal_bin "\x0f\x04\x40\x64\x02hi".b, encode(Frame::Stream.new(stream_id: 4, offset: 100, data: "hi".b, fin: true))
    assert_round_trip(Frame::Stream.new(stream_id: 0, offset: 0, data: "".b, fin: true), Frame::Ping.new)
    assert_round_trip(Frame::Stream.new(stream_id: 2, offset: 7, data: "abc".b))
  end

  # Without a Length field the data runs to the end of the packet; without
  # an Offset field it starts at 0.
  def test_stream_type_bits
    assert_equal [Frame::Stream.new(stream_id: 4, offset: 0, data: "hello".b)], parse("\x08\x04hello")
    assert_equal [Frame::Stream.new(stream_id: 4, offset: 9, data: "\x01".b, fin: true)], parse("\x0d\x04\x09\x01")
    assert_equal [Frame::Stream.new(stream_id: 4, offset: 9, data: "h".b, fin: true), Frame::Ping.new], parse("\x0f\x04\x09\x01h\x01")
  end

  # RFC 9000 "STREAM Frames": data may not end past 2^62 - 1.
  def test_stream_limits
    assert_malformed("\x0c\x00\xff\xff\xff\xff\xff\xff\xff\xffx", ErrorCode::FRAME_ENCODING_ERROR, 0x0c)
    assert_malformed("\x0a\x00\x05abc", ErrorCode::FRAME_ENCODING_ERROR, 0x0a)
    assert_raises(ArgumentError) { Frame::Stream.new(stream_id: 0, offset: Wire::Varint::MAX, data: "x".b) }
  end

  def test_reset_stream_and_stop_sending
    reset = Frame::ResetStream.new(stream_id: 4, error_code: 0x10c, final_size: 1000)
    assert_equal_bin "\x04\x04\x41\x0c\x43\xe8".b, encode(reset)
    stop = Frame::StopSending.new(stream_id: 3, error_code: 0)
    assert_equal_bin "\x05\x03\x00".b, encode(stop)
    assert_round_trip(reset, stop)
    assert_malformed("\x04\x04\x00", ErrorCode::FRAME_ENCODING_ERROR, 0x04)
  end

  def test_flow_control
    frames = [
      Frame::MaxData.new(maximum: 1 << 20), Frame::MaxStreamData.new(stream_id: 4, maximum: 65_536),
      Frame::MaxStreams.new(bidirectional: true, maximum: 100), Frame::MaxStreams.new(bidirectional: false, maximum: 3),
      Frame::DataBlocked.new(maximum: 1 << 20), Frame::StreamDataBlocked.new(stream_id: 4, maximum: 65_536),
      Frame::StreamsBlocked.new(bidirectional: true, maximum: 100), Frame::StreamsBlocked.new(bidirectional: false, maximum: 3)
    ]
    assert_equal_bin "\x12\x40\x64\x13\x03".b, encode(*frames[2, 2])
    assert_equal_bin "\x16\x40\x64\x17\x03".b, encode(*frames[6, 2])
    assert_round_trip(*frames)
  end

  # RFC 9000 "MAX_STREAMS Frames", "STREAMS_BLOCKED Frames": no stream ID
  # can go past 2^60 streams of one direction.
  def test_stream_counts_stop_at_2_to_the_60
    limit = Frame::MAX_STREAM_COUNT
    assert_round_trip(Frame::MaxStreams.new(bidirectional: true, maximum: limit), Frame::StreamsBlocked.new(bidirectional: false, maximum: limit))
    past = Wire::Varint.encode(limit + 1)
    assert_malformed("\x13" + past, ErrorCode::FRAME_ENCODING_ERROR, 0x13)
    assert_malformed("\x16" + past, ErrorCode::FRAME_ENCODING_ERROR, 0x16)
    assert_raises(ArgumentError) { Frame::MaxStreams.new(bidirectional: true, maximum: limit + 1) }
    assert_raises(ArgumentError) { Frame::StreamsBlocked.new(bidirectional: true, maximum: limit + 1) }
  end

  def new_connection_id = Frame::NewConnectionID.new(sequence_number: 2, retire_prior_to: 1, connection_id: "c".b * 8, stateless_reset_token: "t".b * 16)

  def test_connection_ids
    assert_equal_bin "\x18\x02\x01\x08".b + "c".b * 8 + "t".b * 16, encode(new_connection_id)
    assert_round_trip(new_connection_id, Frame::RetireConnectionID.new(sequence_number: 1))
  end

  # RFC 9000 "NEW_CONNECTION_ID Frames".
  def test_new_connection_id_rejects
    assert_malformed("\x18\x01\x02\x08" + "c" * 8 + "t" * 16, ErrorCode::FRAME_ENCODING_ERROR, 0x18)
    assert_malformed("\x18\x02\x01\x00" + "t" * 16, ErrorCode::FRAME_ENCODING_ERROR, 0x18)
    assert_malformed("\x18\x02\x01\x15" + "c" * 21 + "t" * 16, ErrorCode::FRAME_ENCODING_ERROR, 0x18)
    assert_malformed("\x18\x02\x01\x08" + "c" * 8 + "t" * 15, ErrorCode::FRAME_ENCODING_ERROR, 0x18)
    assert_raises(ArgumentError) { new_connection_id.with(retire_prior_to: 3) }
    assert_raises(ArgumentError) { new_connection_id.with(connection_id: "".b) }
    assert_raises(ArgumentError) { new_connection_id.with(stateless_reset_token: "t".b) }
  end

  def test_path_challenge_and_response
    challenge = Frame::PathChallenge.new(data: "12345678".b)
    assert_equal_bin "\x1a12345678\x1b12345678".b, encode(challenge, Frame::PathResponse.new(data: challenge.data))
    assert_round_trip(challenge, Frame::PathResponse.new(data: challenge.data))
    assert_malformed("\x1b1234567", ErrorCode::FRAME_ENCODING_ERROR, 0x1b)
    assert_raises(ArgumentError) { Frame::PathChallenge.new(data: "123".b) }
  end

  def test_connection_close
    transport = Frame::ConnectionClose.new(code: ErrorCode::PROTOCOL_VIOLATION, frame_type: 0x06, reason: "bad".b, application: false)
    assert_equal_bin "\x1c\x0a\x06\x03bad".b, encode(transport)
    application = Frame::ConnectionClose.new(code: 0x0100, frame_type: nil, reason: "".b, application: true)
    assert_equal_bin "\x1d\x41\x00\x00".b, encode(application)
    assert_round_trip(transport, application)
    # The reason is kept as the bytes that came, UTF-8 or not.
    assert_equal "\xff".b, parse("\x1d\x00\x01\xff").first.reason
    assert_malformed("\x1c\x0a\x06\x05bad", ErrorCode::FRAME_ENCODING_ERROR, 0x1c)
  end

  def test_connection_close_misuse
    assert_raises(ArgumentError) { Frame::ConnectionClose.new(code: 0, frame_type: 1, reason: "".b, application: true) }
    assert_raises(ArgumentError) { Frame::ConnectionClose.new(code: 0, frame_type: nil, reason: "".b, application: false) }
  end

  # RFC 9221 "Datagram Frame Types": 0x30 runs to the end of the packet.
  def test_datagram
    assert_equal_bin "\x31\x02hi".b, encode(Frame::Datagram.new(data: "hi".b))
    assert_round_trip(Frame::Datagram.new(data: "hi".b), Frame::Datagram.new(data: "".b), Frame::Ping.new)
    assert_equal [Frame::Datagram.new(data: "hi\x01".b)], parse("\x30hi\x01")
    assert_malformed("\x31\x05hi", ErrorCode::FRAME_ENCODING_ERROR, 0x31)
  end

  # RFC 9000 Table 3: the packets each frame may travel in (Initial,
  # Handshake, 0-RTT, 1-RTT), and the markings N (not ack-eliciting) and P
  # (probing).
  TABLE_3 = {
    Frame::Padding.new(length: 1) => ["IH01", "NP"],
    Frame::Ping.new => ["IH01", ""],
    Frame::Ack.new(ranges: [0..0], delay: 0.0) => ["IH_1", "N"],
    Frame::ResetStream.new(stream_id: 0, error_code: 0, final_size: 0) => ["__01", ""],
    Frame::StopSending.new(stream_id: 0, error_code: 0) => ["__01", ""],
    Frame::Crypto.new(offset: 0, data: "x".b) => ["IH_1", ""],
    Frame::NewToken.new(token: "t".b) => ["___1", ""],
    Frame::Stream.new(stream_id: 0, offset: 0, data: "x".b) => ["__01", ""],
    Frame::MaxData.new(maximum: 0) => ["__01", ""],
    Frame::MaxStreamData.new(stream_id: 0, maximum: 0) => ["__01", ""],
    Frame::MaxStreams.new(bidirectional: true, maximum: 0) => ["__01", ""],
    Frame::DataBlocked.new(maximum: 0) => ["__01", ""],
    Frame::StreamDataBlocked.new(stream_id: 0, maximum: 0) => ["__01", ""],
    Frame::StreamsBlocked.new(bidirectional: false, maximum: 0) => ["__01", ""],
    Frame::NewConnectionID.new(sequence_number: 1, retire_prior_to: 0, connection_id: "c".b, stateless_reset_token: "t".b * 16) => ["__01", "P"],
    Frame::RetireConnectionID.new(sequence_number: 0) => ["__01", ""],
    Frame::PathChallenge.new(data: "x".b * 8) => ["__01", "P"],
    Frame::PathResponse.new(data: "x".b * 8) => ["___1", "P"],
    Frame::ConnectionClose.new(code: 0, frame_type: 0, reason: "".b, application: false) => ["IH01", "N"],
    Frame::ConnectionClose.new(code: 0, frame_type: nil, reason: "".b, application: true) => ["__01", "N"],
    Frame::HandshakeDone.new => ["___1", ""],
    Frame::Datagram.new(data: "x".b) => ["__01", ""]
  }.freeze
  PACKET_TYPES = %i[initial handshake zero_rtt one_rtt].freeze

  def test_table_3
    TABLE_3.each do |frame, (packets, spec)|
      PACKET_TYPES.each_with_index do |packet_type, index|
        permitted = packets[index] != "_"
        assert_equal permitted, frame.permitted_in?(packet_type), "#{frame.class} in #{packet_type}"
        bytes = encode(frame)
        if permitted
          assert_equal [frame], parse(bytes, packet_type:)
        else
          assert_malformed_in(bytes, packet_type, ErrorCode::PROTOCOL_VIOLATION)
        end
      end
      assert_equal !spec.include?("N"), frame.ack_eliciting?, frame.class.name
      assert_equal spec.include?("P"), frame.probing?, frame.class.name
    end
    assert_equal Frame::KINDS.size, TABLE_3.keys.map(&:class).uniq.size
  end

  def assert_malformed_in(bytes, packet_type, code)
    error = assert_raises(Wire::Malformed) { parse(bytes, packet_type:) }
    assert_equal [code, Wire::Reader.new(bytes).varint], [error.code, error.frame_type]
  end

  # The frame type the error names is the one that broke the rule, after
  # frames that kept it.
  def test_packet_type_violation_names_the_frame
    error = assert_raises(Wire::Malformed) { parse("\x01\x1e", packet_type: :handshake) }
    assert_equal [ErrorCode::PROTOCOL_VIOLATION, 0x1e], [error.code, error.frame_type]
  end

  # RFC 9000 "Frames and Frame Types".
  def test_a_packet_carries_a_frame
    assert_malformed("", ErrorCode::PROTOCOL_VIOLATION, nil)
  end

  def test_unknown_frame_types
    assert_malformed("\x1f", ErrorCode::FRAME_ENCODING_ERROR, 0x1f)
    assert_malformed("\x01\x40\xaf", ErrorCode::FRAME_ENCODING_ERROR, 0xaf)
  end

  def test_frame_types_in_their_shortest_encoding
    assert_malformed("\x40\x01", ErrorCode::PROTOCOL_VIOLATION, 0x01)
  end
end
