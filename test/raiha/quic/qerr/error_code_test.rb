require "test_helper"
require "raiha/quic/qerr"

class RaihaQuicQerrErrorCodeTest < Minitest::Test
  def test_description
    assert_equal "No error", Raiha::Quic::Qerr::TransportErrorCode.description(0x00)
    assert_equal "Flow control error", Raiha::Quic::Qerr::TransportErrorCode.description(0x03)
    assert_equal "Generic protocol violation", Raiha::Quic::Qerr::TransportErrorCode.description(0x0a)
    assert_equal "No viable network path exists", Raiha::Quic::Qerr::TransportErrorCode.description(0x10)
  end

  def test_unknown_error_code
    assert_match(/Unknown error/, Raiha::Quic::Qerr::TransportErrorCode.description(0xff))
  end

  def test_crypto_error
    assert_equal 0x0128, Raiha::Quic::Qerr::TransportErrorCode.crypto_error(40)
  end

  def test_crypto_error_description
    description = Raiha::Quic::Qerr::TransportErrorCode.description(0x0128)
    assert_equal "TLS alert: handshake_failure", description
  end

  def test_all_error_codes_have_descriptions
    codes = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]
    codes.each do |code|
      refute_match(/Unknown/, Raiha::Quic::Qerr::TransportErrorCode.description(code),
        "Error code 0x#{code.to_s(16)} should have a description")
    end
  end
end
