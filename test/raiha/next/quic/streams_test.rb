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

  # Streams of a client whose peer, the server, sent these limits.
  def with_peer(**limits)
    s = streams
    s.peer_parameters = QUIC::Config.new(**limits).transport_parameters(initial_source_connection_id: "s".b * 8)
    s
  end

  # MAX_STREAM_DATA is for a part that sends: the server's unidirectional
  # stream only receives here.
  def test_max_stream_data_for_a_stream_that_only_receives
    s = streams
    assert_violation(QUIC::ErrorCode::STREAM_STATE_ERROR) do
      s.receive_max_stream_data(QUIC::Wire::Frame::MaxStreamData.new(stream_id: 3, maximum: 10), now: 0.0)
    end
  end

  # The peer allows one stream; STREAMS_BLOCKED goes once, and MAX_STREAMS
  # lets more open.
  def test_streams_blocked_and_max_streams
    s = with_peer(initial_max_streams_bidi: 1)
    assert_equal 0, s.open(:bidi, now: 0.0)
    assert_nil s.open(:bidi, now: 0.0)
    assert_equal QUIC::Wire::Frame::StreamsBlocked.new(bidirectional: true, maximum: 1), s.next_blocked(100)&.first
    assert_nil s.open(:bidi, now: 0.0)
    assert_nil s.next_blocked(100)
    s.receive_max_streams(QUIC::Wire::Frame::MaxStreams.new(bidirectional: true, maximum: 3))
    assert_equal [4, 8], [s.open(:bidi, now: 0.0), s.open(:bidi, now: 0.0)]
  end

  # A lost DATA_BLOCKED goes again while the limit still holds; not once
  # MAX_DATA has raised it.
  def test_a_lost_blocked_frame
    s = with_peer(initial_max_data: 100)
    stream_id = s.open(:bidi, now: 0.0) || flunk
    s.write(stream_id, "x".b * 200, fin: false)
    frame, duty = s.next_blocked(100)
    assert_equal QUIC::Wire::Frame::DataBlocked.new(maximum: 100), frame
    s.data_blocked_lost(duty)
    assert_equal frame, s.next_blocked(100)&.first
    s.receive_max_data(QUIC::Wire::Frame::MaxData.new(maximum: 300))
    s.data_blocked_lost(duty)
    assert_nil s.next_blocked(100)
  end

  # A blocked peer gets credit not told yet at once.
  def test_data_blocked_brings_credit
    s = streams(initial_max_data: 1000)
    s.receive_stream(stream(1, 0, "x" * 100), now: 0.0)
    s.read(1, 100)
    assert_nil s.next_credit(100, now: 0.0, rtt: nil)
    s.receive_data_blocked(QUIC::Wire::Frame::DataBlocked.new(maximum: 1000))
    assert_equal QUIC::Wire::Frame::MaxData.new(maximum: 1100), s.next_credit(100, now: 0.0, rtt: nil)&.first
  end

  def reset_stream(stream_id, final_size, error_code: 1) = QUIC::Wire::Frame::ResetStream.new(stream_id:, error_code:, final_size:)

  # RESET_STREAM ends a stream as FIN does, and is checked as it is.
  def test_reset_stream_checks
    s = streams(initial_max_stream_data_bidi_remote: 1000)
    s.receive_stream(stream(1, 0, "abc", fin: true), now: 0.0)
    assert_violation(QUIC::ErrorCode::FINAL_SIZE_ERROR) { s.receive_reset_stream(reset_stream(1, 5), now: 0.0) }
    assert_violation(QUIC::ErrorCode::FLOW_CONTROL_ERROR) { s.receive_reset_stream(reset_stream(5, 1001), now: 0.0) }
    assert_violation(QUIC::ErrorCode::STREAM_STATE_ERROR) { s.receive_reset_stream(reset_stream(2, 0), now: 0.0) }
    stop = QUIC::Wire::Frame::StopSending.new(stream_id: 3, error_code: 0)
    assert_violation(QUIC::ErrorCode::STREAM_STATE_ERROR) { s.receive_stop_sending(stop, now: 0.0) }
  end

  # A reset tells the application once, and gives back to the connection
  # what the stream had not read, up to its final size.
  def test_a_reset_gives_credit_back
    events = []
    s = streams(events:)
    s.receive_stream(stream(1, 0, "abc"), now: 0.0)
    s.receive_reset_stream(reset_stream(1, 100), now: 0.0)
    s.receive_reset_stream(reset_stream(1, 100), now: 0.0)
    assert_equal [QUIC::Event::StreamReadable.new(stream_id: 1), QUIC::Event::StreamReset.new(stream_id: 1, error_code: 1, final_size: 100)],
      events
    assert_equal [100, 100], [s.window.received, s.window.consumed]
  end

  # A lost RESET_STREAM goes again until acknowledged; a lost
  # STOP_SENDING, unless the peer has reset the stream since.
  def test_lost_resets_and_stops
    s = with_peer
    stream_id = s.open(:bidi, now: 0.0) || flunk
    s.write(stream_id, "abc".b, fin: false)
    s.reset(stream_id, 5)
    frame, duty = s.next_abandon(100)
    assert_equal QUIC::Wire::Frame::ResetStream.new(stream_id:, error_code: 5, final_size: 0), frame
    s.reset_stream_lost(duty)
    assert_equal frame, s.next_abandon(100)&.first
    s.reset_stream_acked(duty)
    s.reset_stream_lost(duty)
    assert_nil s.next_abandon(100)
    s.receive_stream(stream(1, 0, "x"), now: 0.0)
    s.stop_sending(1, 6)
    _, stop = s.next_abandon(100)
    s.receive_reset_stream(reset_stream(1, 1), now: 0.0)
    s.stop_sending_lost(stop)
    assert_nil s.next_abandon(100)
  end
end
