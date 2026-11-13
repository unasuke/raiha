require "test_helper"
require "raiha/quic"

# The sending part of a stream: frames cut from what was lost and what has
# not gone, FIN with the last data or alone, and the bytes let go as they
# are acknowledged.
class RaihaNextQUICStreamsSenderTest < Minitest::Test
  QUIC = Raiha::Next::QUIC

  def sender(limit: 1000) = QUIC::Streams::Sender.new(stream_id: 4, limit:)

  # Each frame's offset, data and FIN, until none comes.
  def frames(sender, room)
    out = []
    while (frame, duty = sender.next_frame(room))
      assert_equal [frame.stream_id, frame.offset, frame.data.bytesize, frame.fin], [duty.stream_id, duty.offset, duty.length, duty.fin]
      assert_operator QUIC::Wire::Frame.encode([frame], ack_delay_exponent: 0).bytesize, :<=, room
      out << [frame.offset, frame.data, frame.fin]
    end
    out
  end

  def test_frames_fit_their_room
    s = sender
    s.write("a".b * 30, fin: false)
    # The first frame has no Offset field.
    assert_equal [[0, "a" * 17, false], [17, "a" * 13, false]], frames(s, 20)
    refute s.pending?
  end

  # FIN goes with the last of the data, or alone when the data has gone.
  def test_fin
    s = sender
    s.write("abc".b, fin: true)
    assert_equal [[0, "abc", true]], frames(s, 100)
    s = sender
    s.write("abc".b, fin: false)
    frames(s, 100)
    s.write("".b, fin: true)
    assert s.pending?
    assert_equal [[3, "", true]], frames(s, 100)
  end

  # Bytes are let go up to the first one not acknowledged.
  def test_acknowledgments_let_bytes_go
    s = sender
    s.write("abcdef".b, fin: true)
    frames(s, 7)
    assert_equal 6, s.buffered
    assert_equal 0, s.acked(2, 2, false)
    assert_equal 4, s.acked(0, 2, false)
    assert_equal 2, s.buffered
    refute s.all_acked?
    assert_equal 2, s.acked(4, 2, true)
    assert s.all_acked?
  end

  # What was lost goes again before anything new, less what was
  # acknowledged in the meantime, with FIN when that was lost too.
  def test_lost_data_goes_first
    s = sender
    s.write("abcdefgh".b, fin: true)
    frames(s, 9)
    s.write("".b, fin: false)
    s.lost(0, 8, true)
    s.acked(2, 2, false)
    assert_equal [[0, "ab", false], [4, "efgh", true]], frames(s, 100)
  end

  def test_fin_lost_alone
    s = sender
    s.write("ab".b, fin: false)
    frames(s, 100)
    s.write("".b, fin: true)
    frames(s, 100)
    s.acked(0, 2, false)
    s.lost(2, 0, true)
    assert_equal [[2, "", true]], frames(s, 100)
  end

  # The peer's limit only grows.
  def test_the_limit
    s = sender(limit: 100)
    s.write("x".b * 60, fin: false)
    assert_equal 40, s.credit
    refute s.raise_limit(80)
    assert s.raise_limit(200)
    assert_equal 140, s.credit
  end
end
