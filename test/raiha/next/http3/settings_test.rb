require "raiha/next/test_helper"
require "raiha/next/http3"

class RaihaNextHTTP3SettingsTest < Minitest::Test
  HTTP3 = Raiha::Next::HTTP3
  Settings = HTTP3::Settings

  def frame(*pairs) = HTTP3::Frame::Settings.new(settings: pairs)

  # This end's by default: no dynamic table, 64 KiB field sections, no
  # HTTP Datagrams, as QUIC takes no DATAGRAM frames by default; only what
  # differs from the defaults of the RFCs goes.
  def test_this_ends_by_default
    settings = Settings.new
    assert_equal [0, 0, 65_536, false, false], settings.to_h.values
    assert_equal frame([0x06, 65_536]), settings.to_frame
    assert_equal frame([0x06, 65_536], [0x33, 1]), Settings.new(h3_datagram: true).to_frame
  end

  def test_every_setting_in_the_frame
    settings = Settings.new(qpack_max_table_capacity: 4096, qpack_blocked_streams: 16, max_field_section_size: nil, h3_datagram: false,
      enable_connect_protocol: true)
    assert_equal frame([0x01, 4096], [0x07, 16], [0x08, 1]), settings.to_frame
    assert_equal settings, Settings.from_frame(settings.to_frame)
  end

  # What the peer does not say takes the default of the RFCs: no limit on
  # field sections, and neither Extended CONNECT nor HTTP Datagrams.
  def test_the_peers_defaults
    assert_equal Settings.new(max_field_section_size: nil, h3_datagram: false), Settings.from_frame(frame)
  end

  # RFC 9114 "Settings Parameters": those not known are ignored, GREASE
  # among them.
  def test_unknown_settings_are_ignored
    assert_equal Settings.new(max_field_section_size: 100, h3_datagram: false), Settings.from_frame(frame([0x21, 7], [0x06, 100], [0x1f * 4 + 0x21, 0]))
  end

  def test_settings_errors
    [
      frame([0x06, 1], [0x06, 2]), frame([0x00, 0]), frame([0x02, 0]), frame([0x05, 16_384]),
      frame([0x33, 2]), frame([0x08, 7])
    ].each do |bad|
      error = assert_raises(HTTP3::Violation, bad.inspect) { Settings.from_frame(bad) }
      assert_equal HTTP3::ErrorCode::SETTINGS_ERROR, error.code
    end
  end

  def test_arguments_are_checked
    assert_raises(ArgumentError) { Settings.new(qpack_max_table_capacity: -1) }
    assert_raises(ArgumentError) { Settings.new(max_field_section_size: 1 << 62) }
    assert_raises(ArgumentError) { Settings.new(h3_datagram: 1) }
  end

  def test_a_malformed_frame_closes_with_h3_frame_error
    assert_equal HTTP3::ErrorCode::FRAME_ERROR, HTTP3::Frame::Malformed.new("x").code
  end
end
