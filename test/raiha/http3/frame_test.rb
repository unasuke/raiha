require "test_helper"
require "raiha/http3"

class RaihaNextHTTP3FrameTest < Minitest::Test
  Frame = Raiha::HTTP3::Frame

  # Each frame and its bytes: the type, the length, then the payload.
  FRAMES = {
    Frame::Data.new(data: "hello") => "\x00\x05hello",
    Frame::Headers.new(field_section: "\x00\x00\xd1".b) => "\x01\x03\x00\x00\xd1",
    Frame::CancelPush.new(push_id: 3) => "\x03\x01\x03",
    Frame::Settings.new(settings: [[0x01, 0], [0x06, 65_536]]) => "\x04\x07\x01\x00\x06\x80\x01\x00\x00",
    Frame::Settings.new(settings: []) => "\x04\x00",
    Frame::PushPromise.new(push_id: 64, field_section: "\x00\x00".b) => "\x05\x04\x40\x40\x00\x00",
    Frame::GoAway.new(id: 4) => "\x07\x01\x04",
    Frame::MaxPushId.new(push_id: 0) => "\x0d\x01\x00",
    Frame::PriorityUpdate.new(element_id: 0, priority: "u=1") => "\x80\x0f\x07\x00\x04\x00u=1",
    Frame::PriorityUpdate.new(element_id: 2, priority: "", push: true) => "\x80\x0f\x07\x01\x01\x02"
  }.transform_values(&:b).freeze

  def test_encoding_and_decoding
    FRAMES.each do |frame, bytes|
      assert_equal bytes, Frame.encode(frame), frame.inspect
      type, offset = Raiha::HTTP3::Varint.decode(bytes)
      length, offset = Raiha::HTTP3::Varint.decode(bytes, offset)
      assert_equal bytes.bytesize - offset, length
      assert_equal frame, Frame.decode(type, bytes.byteslice(offset..))
    end
  end

  def test_the_header_of_a_payload
    assert_equal "\x00\x40\x40".b, Frame.header(Frame::DATA, 64)
  end

  # Data in any encoding goes as its bytes.
  def test_strings_are_binary
    data = "é" * 40
    frame = Frame::Data.new(data:)
    assert_equal Encoding::BINARY, frame.data.encoding
    assert_equal "\x00\x40\x50".b + data.b, Frame.encode(frame)
  end

  def test_frames_are_shareable
    frames = [
      Frame::Data.new(data: +"x"), Frame::Headers.new(field_section: +"y"), Frame::Settings.new(settings: [[1, 2]]),
      Frame::PushPromise.new(push_id: 1, field_section: +"z"), Frame::PriorityUpdate.new(element_id: 0, priority: +"i")
    ]
    frames.each { |frame| assert Ractor.shareable?(frame), frame.inspect }
  end

  # RFC 9114 "Frame Layout": a payload with bytes past its fields, or that
  # ends before them, is H3_FRAME_ERROR.
  def test_malformed_payloads
    {
      Frame::CANCEL_PUSH => ["", "\x01\x02", "\x40"],
      Frame::SETTINGS => ["\x01", "\x01\x00\x06", "\x01\x40"],
      Frame::PUSH_PROMISE => [""],
      Frame::GOAWAY => ["", "\x04\x00"],
      Frame::MAX_PUSH_ID => ["", "\x80\x00"],
      Frame::PRIORITY_UPDATE => ["", "\x40"]
    }.each do |type, payloads|
      payloads.each do |payload|
        assert_raises(Frame::Malformed, "0x#{type.to_s(16)} #{payload.inspect}") { Frame.decode(type, payload.b) }
      end
    end
  end

  def test_no_decoding_of_other_types
    (Frame::HTTP2_TYPES + [0x21, 0x0e]).each { |type| assert_raises(ArgumentError) { Frame.decode(type, "".b) } }
  end
end
