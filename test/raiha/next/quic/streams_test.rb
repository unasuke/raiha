require "raiha/next/test_helper"
require "raiha/next/quic"

# The streams of a connection receiving STREAM frames: which streams a
# frame may name, and the checks every frame passes before its data is
# kept.
class RaihaNextQUICStreamsTest < Minitest::Test
  QUIC = Raiha::Next::QUIC

  def streams(role: :client, events: [], **config) = QUIC::Streams.new(role:, config: QUIC::Config.new(**config), events:, now: 0.0)

  def stream(stream_id, offset, data, fin: false) = QUIC::Wire::Frame::Stream.new(stream_id:, offset:, data: data.b, fin:)

  def assert_violation(code, &)
    error = assert_raises(QUIC::Violation, &)
    assert_equal code, error.code, error.message
  end

  # A client's own unidirectional stream only sends, and its own streams
  # open when it opens them.
  def test_streams_of_this_end
    s = streams
    assert_violation(QUIC::ErrorCode::STREAM_STATE_ERROR) { s.receive_stream(stream(2, 0, "a"), now: 0.0) }
    assert_violation(QUIC::ErrorCode::STREAM_STATE_ERROR) { s.receive_stream(stream(0, 0, "a"), now: 0.0) }
  end

  # The server's stream 9 opens 1 and 5 with it.
  def test_the_peer_opens_streams_up_to_one
    s = streams
    s.receive_stream(stream(9, 0, "c"), now: 0.0)
    s.receive_stream(stream(1, 0, "a"), now: 0.0)
    s.receive_stream(stream(7, 0, "u"), now: 0.0)
    assert_equal 3, s.window.received
  end

  def test_the_peer_stays_within_the_limit
    s = streams(initial_max_streams_bidi: 2, initial_max_streams_uni: 1)
    s.receive_stream(stream(5, 0, "a"), now: 0.0)
    assert_violation(QUIC::ErrorCode::STREAM_LIMIT_ERROR) { s.receive_stream(stream(9, 0, "a"), now: 0.0) }
    assert_violation(QUIC::ErrorCode::STREAM_LIMIT_ERROR) { s.receive_stream(stream(7, 0, "a"), now: 0.0) }
  end

  # The connection counts how far each stream has been received, however
  # much of it came: streams that never send their first bytes still use
  # the connection's limit up (CVE-2026-75804).
  def test_the_connection_counts_the_furthest_offsets
    s = streams(initial_max_data: 1000, initial_max_stream_data_bidi_remote: 600)
    s.receive_stream(stream(1, 599, "x"), now: 0.0)
    assert_equal 600, s.window.received
    assert_violation(QUIC::ErrorCode::FLOW_CONTROL_ERROR) { s.receive_stream(stream(5, 400, "x"), now: 0.0) }
  end

  # The first rule a frame breaks names the error: the stream's ID, its
  # final size, its limit, the connection's limit.
  def test_the_order_of_the_checks
    s = streams(initial_max_data: 1000, initial_max_stream_data_bidi_remote: 600, initial_max_streams_bidi: 1)
    assert_violation(QUIC::ErrorCode::STREAM_LIMIT_ERROR) { s.receive_stream(stream(5, 5000, "x"), now: 0.0) }
    s.receive_stream(stream(1, 0, "abc", fin: true), now: 0.0)
    assert_violation(QUIC::ErrorCode::FINAL_SIZE_ERROR) { s.receive_stream(stream(1, 5000, "x"), now: 0.0) }
    s = streams(initial_max_data: 100, initial_max_stream_data_bidi_remote: 600)
    assert_violation(QUIC::ErrorCode::FLOW_CONTROL_ERROR) { s.receive_stream(stream(1, 500, "x"), now: 0.0) }
  end

  # A byte at every other offset makes a hole of each; the one past
  # MAX_RECV_GAPS closes the connection.
  def test_at_most_a_thousand_holes
    s = streams(initial_max_data: 10_000, initial_max_stream_data_bidi_remote: 5000, initial_max_streams_bidi: 4)
    QUIC::Streams::MAX_RECV_GAPS.times { |gap| s.receive_stream(stream(1 + 4 * (gap % 2), 2 * (gap / 2) + 1, "x"), now: 0.0) }
    assert_violation(QUIC::ErrorCode::INTERNAL_ERROR) { s.receive_stream(stream(9, 1, "x"), now: 0.0) }
  end
end
