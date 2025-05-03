require "test_helper"
require "raiha/tls/alert"

class RaihaTLSAlertTest < Minitest::Test
  def test_serialize
    illegal_parameter_alert = Raiha::TLS::Alert::ErrorAlert.new(kind: :illegal_parameter)
    assert_equal_bin "\x02\x2f", illegal_parameter_alert.serialize
  end
end
