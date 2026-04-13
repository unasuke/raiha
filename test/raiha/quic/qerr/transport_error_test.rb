require "test_helper"
require "raiha/quic/qerr"

class RaihaQuicQerrTransportErrorTest < Minitest::Test
  def test_transport_error_message
    error = Raiha::Quic::Qerr::TransportError.new(0x03, reason_phrase: "Buffer overflow")
    assert_match(/Flow control error/, error.message)
    assert_match(/Buffer overflow/, error.message)
  end

  def test_transport_error_with_frame_type
    error = Raiha::Quic::Qerr::TransportError.new(0x0a, frame_type: 0x08, reason_phrase: "bad stream")
    assert_match(/frame type: 0x8/, error.message)
  end

  def test_to_connection_close_frame
    error = Raiha::Quic::Qerr::FlowControlError.new("Buffer overflow")
    frame = error.to_connection_close_frame

    assert_equal 0x03, frame.error_code
    assert_equal "Buffer overflow", frame.reason_phrase
    refute frame.application_error
  end

  def test_internal_error
    error = Raiha::Quic::Qerr::InternalError.new("something broke")
    assert_equal 0x01, error.error_code
    assert_match(/Implementation error/, error.message)
  end

  def test_flow_control_error
    error = Raiha::Quic::Qerr::FlowControlError.new
    assert_equal 0x03, error.error_code
  end

  def test_stream_limit_error
    error = Raiha::Quic::Qerr::StreamLimitError.new
    assert_equal 0x04, error.error_code
  end

  def test_stream_state_error_with_frame_type
    error = Raiha::Quic::Qerr::StreamStateError.new(frame_type: 0x08, reason_phrase: "Stream not open")
    assert_equal 0x05, error.error_code
    assert_equal 0x08, error.frame_type

    frame = error.to_connection_close_frame
    assert_equal 0x08, frame.trigger_frame_type
  end

  def test_final_size_error
    error = Raiha::Quic::Qerr::FinalSizeError.new
    assert_equal 0x06, error.error_code
  end

  def test_frame_encoding_error
    error = Raiha::Quic::Qerr::FrameEncodingError.new(frame_type: 0x02)
    assert_equal 0x07, error.error_code
    assert_equal 0x02, error.frame_type
  end

  def test_transport_parameter_error
    error = Raiha::Quic::Qerr::TransportParameterError.new
    assert_equal 0x08, error.error_code
  end

  def test_protocol_violation
    error = Raiha::Quic::Qerr::ProtocolViolation.new(reason_phrase: "unexpected frame")
    assert_equal 0x0a, error.error_code
  end

  def test_crypto_error
    error = Raiha::Quic::Qerr::CryptoError.new(40, reason_phrase: "handshake failure")
    assert_equal 0x0128, error.error_code
    assert_match(/handshake failure/, error.message)
  end
end
