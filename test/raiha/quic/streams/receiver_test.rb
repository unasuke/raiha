require "test_helper"
require "raiha/quic"
require "objspace"

# The receiving part of a stream: data put back in order however it comes,
# read as IO#read reads, and the final size and the stream's limit kept to.
class RaihaNextQUICStreamsReceiverTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
  STREAM = 0x0a

  def receiver(size: 1000) = QUIC::Streams::Receiver.new(window: QUIC::Streams::ReceiveWindow.new(size:, max: size, now: 0.0))

  # Admits and keeps `data` at `offset`.
  def take(receiver, offset, data, fin: false)
    receiver.admit(offset + data.bytesize, fin:, frame_type: STREAM)
    receiver.insert(offset, data.b)
  end

  # "" while nothing is there to read, nil once all of it is read.
  def test_data_in_order
    r = receiver
    assert_equal "".b, r.read(10)
    take(r, 0, "abc")
    take(r, 3, "def", fin: true)
    assert_equal "ab", r.read(2)
    assert_equal "cdef", r.read(10)
    assert_nil r.read(10)
    assert_equal 6, r.window.consumed
  end

  def test_data_out_of_order
    r = receiver
    take(r, 3, "def")
    refute r.readable?
    assert_equal ["".b, 1], [r.read(10), r.gaps]
    take(r, 0, "abc")
    assert_equal [0, "abcdef"], [r.gaps, r.read(10)]
  end

  # What was received before stays; data already read is not kept again.
  def test_overlapping_data
    r = receiver
    take(r, 0, "abcd")
    take(r, 2, "CDef")
    take(r, 1, "XYZ")
    assert_equal "abcdef", r.read(3) + r.read(10)
    take(r, 0, "abcdefgh")
    assert_equal "gh", r.read(10)
  end

  # One frame across several ranges joins them.
  def test_a_frame_across_ranges
    r = receiver
    take(r, 0, "ab")
    take(r, 4, "ef")
    take(r, 8, "ij")
    assert_equal 2, r.gaps
    assert_equal 0, r.gaps_with(1, 8)
    take(r, 1, "bcdefghi")
    assert_equal ["abcdefghij", 0], [r.read(20), r.gaps]
  end

  # RFC 9000 "Stream Final Size".
  def test_the_final_size
    r = receiver
    take(r, 0, "abcdef")
    error = assert_raises(QUIC::Violation) { r.admit(4, fin: true, frame_type: STREAM) }
    assert_equal QUIC::ErrorCode::FINAL_SIZE_ERROR, error.code
    r.admit(10, fin: true, frame_type: STREAM)
    assert_equal 10, r.final_size
    r.admit(8, fin: false, frame_type: STREAM)
    r.admit(10, fin: true, frame_type: STREAM)
    [[11, false], [9, true], [11, true]].each do |end_offset, fin|
      error = assert_raises(QUIC::Violation) { r.admit(end_offset, fin:, frame_type: STREAM) }
      assert_equal [QUIC::ErrorCode::FINAL_SIZE_ERROR, STREAM], [error.code, error.frame_type]
    end
  end

  # The stream's limit, and how much further it has been received, which
  # the connection counts.
  def test_the_stream_limit
    r = receiver(size: 100)
    assert_equal 60, r.admit(60, fin: false, frame_type: STREAM)
    assert_equal 0, r.admit(30, fin: false, frame_type: STREAM)
    assert_equal 40, r.admit(100, fin: false, frame_type: STREAM)
    error = assert_raises(QUIC::Violation) { r.admit(101, fin: false, frame_type: STREAM) }
    assert_equal QUIC::ErrorCode::FLOW_CONTROL_ERROR, error.code
  end

  # The data is copied, never kept as a part of the datagram it came in
  # (CVE-2026-54873).
  def test_data_does_not_keep_the_datagram
    datagram = "\x01".b * 5000
    tail = datagram.byteslice(1000..)
    assert ObjectSpace.dump(tail).include?('"shared":true'), "a substring to the end is shared"
    r = receiver(size: 10_000)
    take(r, 0, tail)
    chunk = r.instance_variable_get(:@ranges).first.data
    refute ObjectSpace.dump(chunk).include?('"shared":true'), "the stream data is shared"
  end

  # Random frames of a known stream: what is read runs on in order and is
  # the stream's, and the holes counted ahead of a frame are those after it.
  def test_random_frames
    rng = Random.new(8)
    20.times do
      bytes = rng.bytes(300)
      r = receiver
      read = "".b
      200.times do
        offset = rng.rand(300)
        length = [rng.rand(1..40), 300 - offset].min
        predicted = r.gaps_with(offset, length)
        take(r, offset, bytes.byteslice(offset, length))
        assert_equal predicted, r.gaps
        read << r.read(rng.rand(1..50)) if rng.rand(3).zero?
        assert_equal bytes.byteslice(0, read.bytesize), read
      end
    end
  end
end
