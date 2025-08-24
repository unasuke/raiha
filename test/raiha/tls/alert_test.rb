require "test_helper"
require "raiha/tls/alert"

class RaihaTLSAlertTest < Minitest::Test
  def test_initialize
    alert = Raiha::TLS::Alert.new(level_num: 1, description_num: 42)
    assert_equal 1, alert.level_num
    assert_equal 42, alert.description_num

    assert_raises do
      Raiha::TLS::Alert.new(description_num: 47)
    end
    assert_raises do
      Raiha::TLS::Alert.new(level_num: 2)
    end
  end

  def test_serialize
    illegal_parameter_alert = Raiha::TLS::Alert.new(level_num: 1, description_num: 47)
    serialized_data = illegal_parameter_alert.serialize
    assert_equal "\x01\x2f", serialized_data
  end

  def test_deserialize_warning_alert
    illegal_parameter_data = "\x01\x2f"
    illegal_parameter_alert = Raiha::TLS::Alert.deserialize(illegal_parameter_data)
    assert illegal_parameter_alert.warning?
  end

  def test_level_and_description
    illegal_parameter_alert = Raiha::TLS::Alert.new(level_num: 1, description_num: 47)
    assert_equal :warning, illegal_parameter_alert.level
    assert_equal :illegal_parameter, illegal_parameter_alert.description

    decrypt_error_alert = Raiha::TLS::Alert.new(level: :fatal, description: :decrypt_error)
    assert_equal :fatal, decrypt_error_alert.level
    assert_equal :decrypt_error, decrypt_error_alert.description
  end

  def test_deserialize_fatal_alert
    illegal_parameter_data = "\x02\x2f"
    illegal_parameter_alert = Raiha::TLS::Alert.deserialize(illegal_parameter_data)
    assert illegal_parameter_alert.fatal?
  end

  def test_level_num_to_sym
    assert_equal :warning, Raiha::TLS::Alert.level_num_to_sym(1)
    assert_equal :fatal, Raiha::TLS::Alert.level_num_to_sym(2)
  end

  def test_description_num_to_sym
    assert_equal :close_notify, Raiha::TLS::Alert.description_num_to_sym(0)
    assert_equal :unexpected_message, Raiha::TLS::Alert.description_num_to_sym(10)
  end
end
