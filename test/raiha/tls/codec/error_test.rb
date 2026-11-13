require "test_helper"
require "raiha/tls"

class RaihaNextTLSCodecErrorTest < Minitest::Test
  Codec = Raiha::Next::TLS::Codec

  def test_syntax_errors_map_to_decode_error
    [Codec::Malformed, Codec::Truncated, Codec::RangeViolation, Codec::TrailingData].each do |klass|
      assert_equal :decode_error, klass.new.alert, klass.name
    end
  end

  def test_placement_errors_map_to_illegal_parameter
    assert_equal :illegal_parameter, Codec::Duplicate.new.alert
    assert_equal :illegal_parameter, Codec::IllegalPlacement.new.alert
  end

  def test_unknown_message_type_maps_to_unexpected_message
    assert_equal :unexpected_message, Codec::UnknownMessageType.new.alert
  end

  def test_every_peer_error_is_malformed
    [Codec::Truncated, Codec::RangeViolation, Codec::TrailingData, Codec::Duplicate,
      Codec::IllegalPlacement, Codec::UnknownMessageType].each do |klass|
      assert_operator klass, :<, Codec::Malformed
    end
    refute_operator Codec::EncodeError, :<, Codec::Malformed
  end
end
