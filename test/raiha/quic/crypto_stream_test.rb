require "test_helper"
require "raiha/quic"

# RFC 9000 "CRYPTO Frames" and "Cryptographic Message Buffering".
class RaihaNextQUICCryptoStreamTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
  Duty = QUIC::Recovery::Duty

  def stream(bytes = nil)
    QUIC::CryptoStream.new(:handshake).tap { _1.write(bytes) if bytes }
  end

  def frames(stream, room)
    taken = []
    while (frame, duty = stream.next_frame(room))
      taken << [frame.offset, frame.data, duty]
    end
    taken
  end

  # Cut to fit the room: the type, the offset, the length and the data; a
  # 2-byte offset leaves one byte less.
  def test_cut_to_fit
    stream = stream("a".b * 3000)
    taken = frames(stream, 1200)
    assert_equal [0, 1196, 2391], taken.map(&:first)
    assert_equal "a".b * 3000, taken.map { _2 }.join
    assert_equal Duty::Crypto.new(space: :handshake, offset: 0, length: 1196), taken.first.last
    refute stream.pending?
    assert_nil stream.next_frame(5)
  end

  # What was lost goes first; what was acknowledged meanwhile does not.
  def test_lost_before_new
    stream = stream("abcdefghij".b)
    frames(stream, 8) # 0..4, 5..9 with 3 bytes of overhead each
    stream.write("XYZ".b)
    stream.acked(2, 2)
    stream.lost(0, 10)
    assert_equal [[0, "ab"], [4, "efghij"], [10, "XYZ"]], frames(stream, 100).map { [_1, _2] }
  end

  # Bytes acknowledged are let go; losing them later sends nothing.
  def test_acknowledged_bytes_are_let_go
    stream = stream("abcdef".b)
    frames(stream, 100)
    stream.acked(0, 6)
    stream.lost(0, 6)
    refute stream.pending?
    stream.write("gh".b)
    assert_equal [[6, "gh"]], frames(stream, 100).map { [_1, _2] }
  end

  def test_reassembly
    stream = stream()
    stream.receive(5, "world".b, limit: 4096)
    assert_equal "", stream.read
    assert_equal 10, stream.buffered
    stream.receive(0, "hel".b, limit: 4096)
    stream.receive(2, "llo".b, limit: 4096)
    assert_equal "helloworld", stream.read
    assert_equal [10, 0], [stream.read_offset, stream.buffered]
    # Old bytes again, and some new beyond them.
    stream.receive(8, "ld!".b, limit: 4096)
    assert_equal "!", stream.read
    stream.receive(0, "hello".b, limit: 4096)
    assert_equal "", stream.read
    assert_equal 11, stream.received_end
  end

  # What waits, to the end of the furthest frame, stays within the limit.
  def test_limit
    stream = stream()
    stream.receive(4095, "x".b, limit: 4096)
    error = assert_raises(QUIC::Violation) { stream.receive(4096, "y".b, limit: 4096) }
    assert_equal [QUIC::ErrorCode::CRYPTO_BUFFER_EXCEEDED, 0x06], [error.code, error.frame_type]
    stream.receive(0, "a".b * 4095, limit: 4096)
    assert_equal 4096, stream.read.bytesize
    stream.receive(4096, "y".b * 4096, limit: 4096)
  end

  # Frames that overlap keep no more than the span waiting: here each
  # reaches the limit from a later offset, which, kept one by one, would
  # hold about half the limit squared.
  def test_overlapping_frames_keep_one_span
    stream = stream()
    (1...4096).each { |offset| stream.receive(offset, "x".b * (4096 - offset), limit: 4096) }
    assert_equal 4096, stream.instance_variable_get(:@window).bytesize
    stream.receive(0, "y".b, limit: 4096)
    assert_equal "y".b + "x".b * 4095, stream.read
  end

  # Bytes received in more than MAX_RANGES pieces fail the connection, so
  # that no frame costs more than the pieces there are.
  def test_too_many_pieces
    stream = stream()
    QUIC::CryptoStream::MAX_RANGES.times { |n| stream.receive(1 + 2 * n, "x".b, limit: 1 << 20) }
    error = assert_raises(QUIC::Violation) { stream.receive(1 + 2 * QUIC::CryptoStream::MAX_RANGES, "x".b, limit: 1 << 20) }
    assert_equal QUIC::ErrorCode::CRYPTO_BUFFER_EXCEEDED, error.code
  end

  # The gaps filled in any order join up.
  def test_pieces_join
    stream = stream()
    [4, 0, 2, 1, 3].each { |n| stream.receive(n * 10, "#{n}".b * 10, limit: 4096) }
    assert_equal "0" * 10 + "1" * 10 + "2" * 10 + "3" * 10 + "4" * 10, stream.read
  end

  # A frame without bytes changes nothing, however far it says it starts.
  def test_empty_frames
    stream = stream()
    (QUIC::CryptoStream::MAX_RANGES + 10).times { |n| stream.receive(10 + 2 * n, "".b, limit: 4096) }
    assert_equal [0, 0], [stream.received_end, stream.buffered]
  end
end
