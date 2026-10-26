require "raiha/next/test_helper"
require "raiha/next/support/http3_pair"

# The peer's control stream (RFC 9114 "Control Streams"): SETTINGS first
# and once, and only the frames a control stream carries.
class RaihaNextHTTP3ConnectionControlStreamTest < Minitest::Test
  include NextHTTP3Pair

  Frame = HTTP3::Frame
  SETTINGS = Frame.encode(HTTP3::Settings.new(max_field_section_size: 1000).to_frame)

  def events(connection) = [].tap { |all| connection.each_event { all << _1 } }

  # `connection` given the peer's control stream with `bytes` after its
  # type: the error code it closed with, or nil.
  def closed_with(connection, bytes, stream_id: 2)
    connection.stream_data(stream_id, "\x00".b + bytes.b)
    actions(connection).grep(HTTP3::Action::Close).first&.error_code
  end

  def test_the_peers_settings
    server = HTTP3::Connection.server
    assert_nil server.peer_settings
    assert_nil closed_with(server, SETTINGS)
    settings = HTTP3::Settings.new(max_field_section_size: 1000)
    assert_equal settings, server.peer_settings
    assert_equal [HTTP3::Event::Settings.new(settings:)], events(server)
  end

  def test_a_byte_at_a_time
    server = HTTP3::Connection.server
    ("\x00".b + SETTINGS).each_char { |byte| server.stream_data(2, byte) }
    assert_equal 1000, server.peer_settings&.max_field_section_size
  end

  def test_settings_must_come_first
    [Frame.encode(Frame::GoAway.new(id: 0)), "\x21\x00".b, Frame.encode(Frame::MaxPushId.new(push_id: 0))].each do |first|
      assert_equal HTTP3::ErrorCode::MISSING_SETTINGS, closed_with(HTTP3::Connection.server, first + SETTINGS)
    end
  end

  def test_frames_a_control_stream_does_not_carry
    [
      SETTINGS, Frame.encode(Frame::Data.new(data: "x")), Frame.encode(Frame::Headers.new(field_section: "\x00\x00")),
      Frame.encode(Frame::PushPromise.new(push_id: 0, field_section: "\x00\x00")), "\x02\x00".b, "\x06\x00".b, "\x08\x00".b, "\x09\x00".b
    ].each do |frame|
      assert_equal HTTP3::ErrorCode::FRAME_UNEXPECTED, closed_with(HTTP3::Connection.server, SETTINGS + frame), frame.inspect
    end
  end

  # MAX_PUSH_ID and PRIORITY_UPDATE go only from a client.
  def test_frames_only_a_client_sends
    [Frame::MaxPushId.new(push_id: 0), Frame::PriorityUpdate.new(element_id: 0, priority: "u=1")].each do |frame|
      assert_equal HTTP3::ErrorCode::FRAME_UNEXPECTED, closed_with(HTTP3::Connection.client, SETTINGS + Frame.encode(frame), stream_id: 3)
      assert_nil closed_with(HTTP3::Connection.server, SETTINGS + Frame.encode(frame))
    end
  end

  def test_frames_not_known_are_passed_over
    assert_nil closed_with(HTTP3::Connection.server, SETTINGS + "\x21\x03abc\x40\x21\x00".b)
  end

  def test_a_frame_too_long
    long = Frame.encode(Frame::Settings.new(settings: [[0x21, 0]] * 8193))
    assert_operator long.bytesize, :>, HTTP3::Connection::MAX_CONTROL_FRAME
    assert_equal HTTP3::ErrorCode::EXCESSIVE_LOAD, closed_with(HTTP3::Connection.server, long)
  end

  def test_settings_that_do_not_hold
    assert_equal HTTP3::ErrorCode::SETTINGS_ERROR, closed_with(HTTP3::Connection.server, "\x04\x04\x06\x01\x06\x02".b)
    assert_equal HTTP3::ErrorCode::FRAME_ERROR, closed_with(HTTP3::Connection.server, "\x04\x01\x06".b)
  end
end
