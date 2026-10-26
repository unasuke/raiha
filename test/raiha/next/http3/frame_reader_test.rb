require "raiha/next/test_helper"
require "raiha/next/http3"

class RaihaNextHTTP3FrameReaderTest < Minitest::Test
  HTTP3 = Raiha::Next::HTTP3
  Frame = HTTP3::Frame
  Reader = HTTP3::FrameReader

  # What a reader with `max_payload` yields for `chunks`, fed one after
  # another.
  def items(*chunks, max_payload: 1000)
    reader = Reader.new(max_payload:)
    [].tap { |all| chunks.each { |chunk| reader.feed(chunk.b) { all << _1 } } }
  end

  def started(type, length) = Reader::Started.new(type:, length:)

  def data(text) = Frame::Data.new(data: text)

  def test_frames_one_after_another
    settings = Frame::Settings.new(settings: [[1, 0]])
    headers = Frame::Headers.new(field_section: "\x00\x00".b)
    bytes = Frame.encode(settings) + Frame.encode(headers) + Frame.encode(data("hi"))
    assert_equal [started(4, 2), settings, started(1, 2), headers, started(0, 2), data("hi")], items(bytes)
  end

  # Fed a byte at a time, the same frames come; DATA in the pieces it came
  # in, each before the frame is whole.
  def test_a_byte_at_a_time
    goaway = Frame::GoAway.new(id: 64)
    bytes = Frame.encode(goaway) + Frame.encode(data("abc"))
    assert_equal [started(7, 2), goaway, started(0, 3), data("a"), data("b"), data("c")], items(*bytes.chars)
  end

  def test_a_header_cut_anywhere
    frame = Frame::PriorityUpdate.new(element_id: 1 << 20, priority: "u=0")
    bytes = Frame.encode(frame)
    (1...bytes.bytesize).each do |cut|
      assert_equal [started(Frame::PRIORITY_UPDATE, 7), frame], items(bytes.byteslice(0, cut), bytes.byteslice(cut..)), cut
    end
  end

  def test_an_empty_data_frame_still_comes
    assert_equal [started(0, 0), data(""), started(0, 0), data("")], items("\x00\x00\x00\x00")
  end

  # A held frame past max_payload is told, and its payload passed over;
  # what follows is read.
  def test_a_held_frame_too_long
    headers = Frame.encode(Frame::Headers.new(field_section: "x" * 20))
    after = Frame.encode(Frame::MaxPushId.new(push_id: 1))
    assert_equal [started(1, 20), Reader::TooLong.new(type: 1, length: 20), started(0x0d, 1), Frame::MaxPushId.new(push_id: 1)],
      items(headers, after, max_payload: 19)
    assert_equal [started(1, 20), Frame::Headers.new(field_section: "x" * 20)], items(headers, max_payload: 20)
  end

  # The payloads of reserved and unknown types are passed over; only their
  # beginning comes.
  def test_frames_passed_over
    bytes = "\x21\x03abc" + "\x06\x01x" + Frame.encode(data("ok"))
    assert_equal [started(0x21, 3), started(0x06, 1), started(0, 2), data("ok")], items(bytes)
  end

  # A length the bytes never reach sets nothing aside.
  def test_a_length_not_trusted
    reader = Reader.new(max_payload: 1000)
    seen = []
    reader.feed("\x21\xc0\x00\x01\x00\x00\x00\x00\x00abc".b) { seen << _1 }
    assert_equal [started(0x21, 1 << 40)], seen
    assert reader.mid_frame?
    seen.clear
    reader.feed("\x00\xc0\x00\x01\x00\x00\x00\x00\x00".b) { seen << _1 }
    assert_empty seen
  end

  def test_mid_frame
    reader = Reader.new(max_payload: 1000)
    refute reader.mid_frame?
    reader.feed("\x00".b) { nil }
    assert reader.mid_frame?
    reader.feed("\x02a".b) { nil }
    assert reader.mid_frame?
    reader.feed("b".b) { nil }
    refute reader.mid_frame?
  end

  def test_a_payload_that_does_not_decode
    assert_raises(Frame::Malformed) { items("\x07\x02\x04\x00") }
  end

  def test_what_comes_is_shareable
    items(Frame.encode(Frame::Settings.new(settings: [[6, 100]])), Frame.encode(data("x" * 10))).each do |item|
      assert Ractor.shareable?(item), item.inspect
    end
  end
end
