require "test_helper"
require "support/quic_pair"

# A server Connection receiving a stream: the application hears when there
# is something to read, reads it as IO#read reads, and the peer gets
# credit back as it does.
class RaihaQUICConnectionStreamReceiveTest < Minitest::Test
  include QUICPair

  def setup
    @keylog = Keylog.new
    @client = client_connection(keylog: @keylog)
  end

  # A server done with the handshake, and its connection ID.
  def server_with(**config)
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

  # The client's 1-RTT packet of `frames`, given to `server`.
  def send_frames(server, *frames, now: 0.1)
    payload = QUIC::Wire::Frame.encode(frames, ack_delay_exponent: 3)
    server.receive(client_one_rtt(@keylog, dcid: @server_id, payload:, packet_number: @number += 1), from: CLIENT, now:)
  end

  def stream(offset, data, stream_id: 0, fin: false) = QUIC::Wire::Frame::Stream.new(stream_id:, offset:, data: data.b, fin:)

  def events(connection) = [].tap { |all| connection.each_event { all << _1 } }

  # The frames of the server's 1-RTT packets now.
  def server_frames(server, now: 0.2)
    server.transmits(now:).flat_map { |transmit| server_one_rtt(@keylog, transmit.payload, phase: 0)&.last || [] }
  end

  def test_reading_a_stream
    server = server_with
    send_frames(server, stream(0, "hello "))
    assert_equal [QUIC::Event::StreamReadable.new(stream_id: 0)], events(server)
    assert_equal [0], server.readable_streams.to_a
    assert_equal "hel", server.stream_read(0, 3)
    assert_equal "lo ", server.stream_read(0, 100)
    assert_equal "".b, server.stream_read(0, 100)
    assert_empty server.readable_streams.to_a
    send_frames(server, stream(6, "world", fin: true))
    assert_equal "world", server.stream_read(0, 100)
    assert_equal [0], server.readable_streams.to_a
    assert_nil server.stream_read(0, 100)
    assert_empty server.readable_streams.to_a
  end

  # Once when there comes something to read; again after the application
  # has read all there was.
  def test_readable_once_until_read
    server = server_with
    send_frames(server, stream(3, "def"))
    assert_empty events(server)
    send_frames(server, stream(0, "abc"))
    send_frames(server, stream(6, "ghi"))
    assert_equal 1, events(server).size
    server.stream_read(0, 100)
    send_frames(server, stream(9, "jkl"))
    assert_equal [QUIC::Event::StreamReadable.new(stream_id: 0)], events(server)
  end

  def test_no_stream_to_read
    server = server_with
    assert_raises(QUIC::Error::StreamError) { server.stream_read(4, 10) }
  end

  # A quarter of the window read brings MAX_STREAM_DATA of what was read
  # plus the window; nothing read, no credit.
  def test_credit_goes_back_as_the_data_is_read
    server = server_with(initial_max_stream_data_bidi_remote: 4000, initial_max_data: 100_000)
    send_frames(server, stream(0, "x" * 1100))
    assert_empty server_frames(server).grep(QUIC::Wire::Frame::MaxStreamData)
    server.stream_read(0, 999)
    assert_empty server_frames(server).grep(QUIC::Wire::Frame::MaxStreamData)
    server.stream_read(0, 1)
    assert_equal [QUIC::Wire::Frame::MaxStreamData.new(stream_id: 0, maximum: 5000)], server_frames(server).grep(QUIC::Wire::Frame::MaxStreamData)
  end

  def test_connection_credit
    server = server_with(initial_max_stream_data_bidi_remote: 4000, initial_max_data: 4000)
    send_frames(server, stream(0, "x" * 1000), stream(0, "y" * 1000, stream_id: 4))
    server.stream_read(0, 1000)
    assert_equal [QUIC::Wire::Frame::MaxData.new(maximum: 5000)], server_frames(server).grep(QUIC::Wire::Frame::MaxData)
  end

  # Data past the stream's limit closes the connection.
  def test_past_the_limit
    server = server_with(initial_max_stream_data_bidi_remote: 1000)
    send_frames(server, stream(1000, "x"))
    assert_equal QUIC::ErrorCode::FLOW_CONTROL_ERROR, server.close_reason&.code
  end
end
