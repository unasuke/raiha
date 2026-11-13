require "test_helper"
require "support/quic_pair"

# Frames of the client that break the rules of streams and flow control,
# given to a server Connection: each closes the connection with the code
# RFC 9000 gives it, a frame that breaks two with the code of the check
# made first, and data sent a byte at a time with a hole after each with
# INTERNAL_ERROR, once the holes are more than the limit.
class RaihaQUICConnectionStreamViolationsTest < Minitest::Test
  include QUICPair

  Frame = QUIC::Wire::Frame
  ErrorCode = QUIC::ErrorCode

  # A server done with the handshake with a client of its own, and its
  # connection ID.
  def server_with(**config)
    @keylog = Keylog.new
    @client = client_connection(keylog: @keylog)
    server = server_connection(config: QUIC::Config.new(**config))
    first = @client.transmits(now: 0.0).first.payload
    server.receive(first, from: CLIENT, now: 0.0)
    reply = server.transmits(now: 0.0)
    @server_id = QUIC::Wire::Packet.parse(reply.first.payload, dcid_length: 8).header.scid
    reply.each { @client.receive(_1.payload, from: SERVER, now: 0.0) }
    handshake(@client, server)
    server.each_event { nil }
    @number = 1000
    server
  end

  # The client's 1-RTT packet of `payload`, given to `server`.
  def send_payload(server, payload)
    server.receive(client_one_rtt(@keylog, dcid: @server_id, payload:, packet_number: @number += 1), from: CLIENT, now: 0.1)
  end

  def send_frames(server, *frames) = send_payload(server, Frame.encode(frames, ack_delay_exponent: 3))

  def stream(stream_id, offset, data, fin: false) = Frame::Stream.new(stream_id:, offset:, data: data.b, fin:)

  def reset_stream(stream_id, final_size) = Frame::ResetStream.new(stream_id:, error_code: 1, final_size:)

  # The code and frame type `server` closed with.
  def closed_with(server)
    error = server.close_reason or flunk "the server did not close"
    [error.code, error.frame_type]
  end

  # A count of streams past 2^60 does not read.
  def test_a_count_of_streams_past_the_largest
    [0x12, 0x13, 0x16, 0x17].each do |type|
      server = server_with
      send_payload(server, QUIC::Wire::Varint.encode(type) + QUIC::Wire::Varint.encode((1 << 60) + 1))
      assert_equal ErrorCode::FRAME_ENCODING_ERROR, server.close_reason&.code, format("0x%02x", type)
    end
  end

  # Frames that the part of the stream they name does not take, and frames
  # for the server's streams it has not opened.
  def test_the_state_of_the_stream
    {
      stream(3, 0, "a") => 0x08,
      reset_stream(3, 0) => 0x04,
      Frame::StreamDataBlocked.new(stream_id: 3, maximum: 0) => 0x15,
      Frame::MaxStreamData.new(stream_id: 2, maximum: 10) => 0x11,
      Frame::StopSending.new(stream_id: 2, error_code: 0) => 0x05,
      Frame::MaxStreamData.new(stream_id: 1, maximum: 10) => 0x11,
      stream(1, 0, "a") => 0x08,
    }.each do |frame, type|
      server = server_with
      send_frames(server, frame)
      assert_equal [ErrorCode::STREAM_STATE_ERROR, type], closed_with(server), frame.inspect
    end
  end

  # A stream the client opens past the limit the server gave, whatever
  # frame opens it.
  def test_the_count_of_streams
    {
      stream(8, 0, "a") => 0x08,
      Frame::MaxStreamData.new(stream_id: 8, maximum: 10) => 0x11,
      Frame::StopSending.new(stream_id: 8, error_code: 0) => 0x05,
      reset_stream(14, 0) => 0x04,
    }.each do |frame, type|
      server = server_with(initial_max_streams_bidi: 2, initial_max_streams_uni: 3)
      send_frames(server, stream(4, 0, "a"))
      refute server.closing?
      send_frames(server, frame)
      assert_equal [ErrorCode::STREAM_LIMIT_ERROR, type], closed_with(server), frame.inspect
    end
  end

  # A final size that differs from the one known, data past it, and a
  # final size under the data received.
  def test_the_final_size
    [
      [stream(0, 0, "abc", fin: true), reset_stream(0, 5), 0x04],
      [stream(0, 0, "abc", fin: true), stream(0, 3, "d"), 0x08],
      [stream(0, 0, "abcdef"), stream(0, 0, "ab", fin: true), 0x08],
      [stream(0, 0, "abcdef"), reset_stream(0, 4), 0x04],
    ].each do |first, second, type|
      server = server_with
      send_frames(server, first)
      send_frames(server, second)
      assert_equal [ErrorCode::FINAL_SIZE_ERROR, type], closed_with(server), second.inspect
    end
  end

  # Data, or a final size, past MAX_STREAM_DATA.
  def test_the_stream_limit
    [[stream(0, 999, "xy"), 0x08], [reset_stream(0, 1001), 0x04]].each do |frame, type|
      server = server_with(initial_max_stream_data_bidi_remote: 1000)
      send_frames(server, stream(0, 0, "x" * 1000))
      refute server.closing?
      send_frames(server, frame)
      assert_equal [ErrorCode::FLOW_CONTROL_ERROR, type], closed_with(server), frame.inspect
    end
  end

  # What a stream adds to how far the streams have been received, past
  # MAX_DATA.
  def test_the_connection_limit
    [[stream(4, 0, "y" * 1001), 0x08], [reset_stream(4, 1001), 0x04]].each do |frame, type|
      server = server_with(initial_max_data: 2000)
      send_frames(server, stream(0, 998, "xx"))
      refute server.closing?
      send_frames(server, frame)
      assert_equal [ErrorCode::FLOW_CONTROL_ERROR, type], closed_with(server), frame.inspect
    end
  end

  # MAX_DATA, MAX_STREAM_DATA and MAX_STREAMS lower than what the client
  # gave before change nothing.
  def test_limits_that_do_not_grow
    server = server_with
    send_frames(server, Frame::MaxData.new(maximum: 10), Frame::MaxStreams.new(bidirectional: true, maximum: 1))
    stream_id = server.open_stream || flunk
    send_frames(server, Frame::MaxStreamData.new(stream_id:, maximum: 10))
    refute server.closing?
    assert_equal 2000, server.stream_write(stream_id, "x" * 2000)
    refute_nil server.open_stream
  end

  # A frame that breaks two rules closes with the code of the check made
  # first: the stream's ID, its final size, its limit, the connection's.
  def test_the_first_check_broken_names_the_error
    [
      [[], stream(3, 100_000, "x"), ErrorCode::STREAM_STATE_ERROR],
      [[], stream(8, 100_000, "x"), ErrorCode::STREAM_LIMIT_ERROR],
      [[stream(0, 0, "abc", fin: true)], stream(0, 100_000, "x"), ErrorCode::FINAL_SIZE_ERROR],
    ].each do |before, frame, code|
      server = server_with(initial_max_streams_bidi: 2, initial_max_stream_data_bidi_remote: 1000, initial_max_data: 500)
      before.each { send_frames(server, _1) }
      send_frames(server, frame)
      assert_equal code, server.close_reason&.code, frame.inspect
    end
    server = server_with(initial_max_stream_data_bidi_remote: 1000, initial_max_data: 500)
    send_frames(server, stream(0, 1999, "x"))
    assert_equal "data up to 2000 past the limit 1000", server.close_reason&.reason
  end

  # A byte with a hole before it, as many times as there may be holes,
  # keeps the connection; one more closes it.
  def test_data_a_byte_at_a_time
    server = server_with
    config = QUIC::Config.new
    holes = config.max_receive_window / config.initial_max_datagram_size
    offsets = (0..holes).map { 2 * _1 + 1 }
    offsets[0...holes].each_slice(120) { |slice| send_frames(server, *slice.map { stream(0, _1, "x") }) }
    refute server.closing?
    send_frames(server, stream(0, offsets.last, "x"))
    assert_equal [ErrorCode::INTERNAL_ERROR, 0x08], closed_with(server)
  end
end
