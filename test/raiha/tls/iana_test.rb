require "test_helper"
require "raiha/tls"

class RaihaTLSIANATest < Minitest::Test
  IANA = Raiha::TLS::IANA

  def test_cipher_suite_name
    assert_equal :TLS_AES_128_GCM_SHA256, IANA.cipher_suite_name(0x1301)
    assert_nil IANA.cipher_suite_name(0x0a0a)
  end

  def test_alert_name_and_code
    assert_equal :decode_error, IANA.alert_name(50)
    assert_nil IANA.alert_name(21)
    assert_equal 47, IANA.alert_code(:illegal_parameter)
    assert_raises(KeyError) { IANA.alert_code(:no_such_alert) }
  end

  def test_alert_codes_invert_alerts
    IANA::ALERTS.each { |code, name| assert_equal code, IANA.alert_code(name) }
  end

  def test_label
    assert_equal "key_share", IANA.label(IANA::EXTENSIONS, 51)
    assert_equal "x25519", IANA.label(IANA::NAMED_GROUPS, 0x001d)
    assert_equal "unknown(0x0a0a)", IANA.label(IANA::NAMED_GROUPS, 0x0a0a)
    assert_equal "unknown(0xfe00)", IANA.label(IANA::EXTENSIONS, 0xfe00)
  end

  def test_grease
    grease = (0x0..0xf).map { |n| (n << 12) | 0x0a00 | (n << 4) | 0x0a }
    assert_equal 16, grease.size
    grease.each { |v| assert IANA.grease?(v), format("0x%04x", v) }
    [0x0a1a, 0x1a0a, 0x0b0b, 0x001d, 0x1301, 0x0000, 0xffff].each do |v|
      refute IANA.grease?(v), format("0x%04x", v)
    end
  end

  def test_tables_are_shareable
    [IANA::CIPHER_SUITES, IANA::NAMED_GROUPS, IANA::EXTENSIONS, IANA::ALERTS, IANA::ALERT_CODES].each do |table|
      assert Ractor.shareable?(table)
    end
  end
end
