require "test_helper"
require "raiha/http3/frame"

class RaihaHTTP3FrameTest < Minitest::Test
  def test_data_frame_roundtrip
    frame = Raiha::HTTP3::DataFrame.new("hello".b)
    bytes = frame.serialize

    parsed = Raiha::HTTP3::Frame.parse(Raiha::Quic::Wire::Buffer.new(bytes))
    assert_instance_of Raiha::HTTP3::DataFrame, parsed
    assert_equal "hello", parsed.data
  end

  def test_data_frame_empty_payload
    frame = Raiha::HTTP3::DataFrame.new("".b)
    bytes = frame.serialize

    parsed = Raiha::HTTP3::Frame.parse(Raiha::Quic::Wire::Buffer.new(bytes))
    assert_equal "".b, parsed.data
  end

  def test_headers_frame_roundtrip
    encoded = "\x00\x00\xc0\x81".b # placeholder encoded field section
    frame = Raiha::HTTP3::HeadersFrame.new(encoded)
    bytes = frame.serialize

    parsed = Raiha::HTTP3::Frame.parse(Raiha::Quic::Wire::Buffer.new(bytes))
    assert_instance_of Raiha::HTTP3::HeadersFrame, parsed
    assert_equal encoded, parsed.encoded_field_section
  end

  def test_settings_frame_roundtrip
    frame = Raiha::HTTP3::SettingsFrame.new
    frame.settings[Raiha::HTTP3::SettingsFrame::SETTINGS[:qpack_max_table_capacity]] = 100
    frame.settings[Raiha::HTTP3::SettingsFrame::SETTINGS[:max_field_section_size]] = 16384

    bytes = frame.serialize

    parsed = Raiha::HTTP3::Frame.parse(Raiha::Quic::Wire::Buffer.new(bytes))
    assert_instance_of Raiha::HTTP3::SettingsFrame, parsed
    assert_equal 100, parsed.qpack_max_table_capacity
    assert_equal 16384, parsed.max_field_section_size
  end

  def test_settings_frame_default_values
    frame = Raiha::HTTP3::SettingsFrame.new
    bytes = frame.serialize

    parsed = Raiha::HTTP3::Frame.parse(Raiha::Quic::Wire::Buffer.new(bytes))
    assert_equal 0, parsed.qpack_max_table_capacity
    assert_equal 0, parsed.qpack_blocked_streams
    assert_nil parsed.max_field_section_size
  end

  def test_goaway_frame_roundtrip
    frame = Raiha::HTTP3::GoawayFrame.new(42)
    bytes = frame.serialize

    parsed = Raiha::HTTP3::Frame.parse(Raiha::Quic::Wire::Buffer.new(bytes))
    assert_instance_of Raiha::HTTP3::GoawayFrame, parsed
    assert_equal 42, parsed.stream_id
  end

  def test_cancel_push_frame_roundtrip
    frame = Raiha::HTTP3::CancelPushFrame.new(7)
    bytes = frame.serialize

    parsed = Raiha::HTTP3::Frame.parse(Raiha::Quic::Wire::Buffer.new(bytes))
    assert_instance_of Raiha::HTTP3::CancelPushFrame, parsed
    assert_equal 7, parsed.push_id
  end

  def test_push_promise_frame_roundtrip
    frame = Raiha::HTTP3::PushPromiseFrame.new(3, "encoded".b)
    bytes = frame.serialize

    parsed = Raiha::HTTP3::Frame.parse(Raiha::Quic::Wire::Buffer.new(bytes))
    assert_instance_of Raiha::HTTP3::PushPromiseFrame, parsed
    assert_equal 3, parsed.push_id
    assert_equal "encoded", parsed.encoded_field_section
  end

  def test_max_push_id_frame_roundtrip
    frame = Raiha::HTTP3::MaxPushIdFrame.new(1000)
    bytes = frame.serialize

    parsed = Raiha::HTTP3::Frame.parse(Raiha::Quic::Wire::Buffer.new(bytes))
    assert_instance_of Raiha::HTTP3::MaxPushIdFrame, parsed
    assert_equal 1000, parsed.push_id
  end

  def test_unknown_frame_preserved
    # Build an unknown frame type manually: varint type 0x42, varint length 2, 2 bytes payload
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(0x42)
    buf.write_varint(2)
    buf.write("ab".b)

    parsed = Raiha::HTTP3::Frame.parse(Raiha::Quic::Wire::Buffer.new(buf.to_s))
    assert_instance_of Raiha::HTTP3::UnknownFrame, parsed
    assert_equal 0x42, parsed.frame_type
    assert_equal "ab".b, parsed.payload
  end

  def test_multiple_frames_in_sequence
    frames = [
      Raiha::HTTP3::HeadersFrame.new("\xc0\x81".b),
      Raiha::HTTP3::DataFrame.new("body".b),
    ]
    bytes = frames.map(&:serialize).join

    buffer = Raiha::Quic::Wire::Buffer.new(bytes)
    parsed1 = Raiha::HTTP3::Frame.parse(buffer)
    parsed2 = Raiha::HTTP3::Frame.parse(buffer)

    assert_instance_of Raiha::HTTP3::HeadersFrame, parsed1
    assert_instance_of Raiha::HTTP3::DataFrame, parsed2
    assert_equal "body", parsed2.data
  end
end
