require "raiha/next/test_helper"
require "raiha/next/quic"

class RaihaNextQUICWireFrameTest < Minitest::Test
  Wire = Raiha::Next::QUIC::Wire
  Frame = Wire::Frame
  ErrorCode = Raiha::Next::QUIC::ErrorCode

  def parse(bytes) = Frame.parse(bytes.b, ack_delay_exponent: 3)

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
