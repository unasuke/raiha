require "raiha/next/test_helper"
require "raiha/next/http3/qpack"

class RaihaNextQPACKValuesTest < Minitest::Test
  QPACK = Raiha::Next::HTTP3::QPACK

  # RFC 9204 "Error Code Registration".
  def test_error_codes
    assert_equal 0x0200, QPACK::ErrorCode::DECOMPRESSION_FAILED
    assert_equal 0x0201, QPACK::ErrorCode::ENCODER_STREAM_ERROR
    assert_equal 0x0202, QPACK::ErrorCode::DECODER_STREAM_ERROR
  end
end
