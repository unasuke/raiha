require "test_helper"
require "raiha/quic/qerr"

class RaihaQuicQerrApplicationErrorTest < Minitest::Test
  def test_application_error
    error = Raiha::Quic::Qerr::ApplicationError.new(0x0100, reason_phrase: "no error")
    assert_equal 0x0100, error.error_code
    assert_match(/Application Error/, error.message)
  end

  def test_to_connection_close_frame
    error = Raiha::Quic::Qerr::ApplicationError.new(0x0101, reason_phrase: "protocol error")
    frame = error.to_connection_close_frame

    assert_equal 0x0101, frame.error_code
    assert_equal "protocol error", frame.reason_phrase
    assert frame.application_error
    assert_nil frame.trigger_frame_type
  end

  def test_http3_error_codes
    assert_equal 0x0100, Raiha::Quic::Qerr::Http3ErrorCode::H3_NO_ERROR
    assert_equal 0x0101, Raiha::Quic::Qerr::Http3ErrorCode::H3_GENERAL_PROTOCOL_ERROR
    assert_equal 0x0102, Raiha::Quic::Qerr::Http3ErrorCode::H3_INTERNAL_ERROR
    assert_equal 0x010c, Raiha::Quic::Qerr::Http3ErrorCode::H3_REQUEST_CANCELLED
  end
end
