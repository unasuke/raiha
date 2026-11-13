require "test_helper"
require "support/quic_pair"

# DATAGRAM frames (RFC 9221) between two Connections: sent only to a peer
# that takes them, never again, in order of urgency; received as events
# while the application keeps up, and dropped when it does not.
class RaihaQUICConnectionDatagramTest < Minitest::Test
  include QUICPair

  WITH_DATAGRAMS = QUIC::Config.new(max_datagram_frame_size: 65_535)

  def connected(client_config: WITH_DATAGRAMS, server_config: WITH_DATAGRAMS)
    @keylog = Keylog.new
    client = client_connection(config: client_config, keylog: @keylog)
    server = server_connection(config: server_config)
    first = client.transmits(now: 0.0)
    first.each { server.receive(_1.payload, from: CLIENT, now: 0.0) }
    reply = server.transmits(now: 0.0)
    @server_id = QUIC::Wire::Packet.parse(reply.first.payload, dcid_length: 8).header.scid
    reply.each { client.receive(_1.payload, from: SERVER, now: 0.0) }
    now = exchange(client, server, now: handshake(client, server), rounds: 3)
    [client, server].each { |connection| connection.each_event { nil } }
    [client, server, now]
  end

  def exchange(client, server, now:, rounds: 5)
    rounds.times do
      client.transmits(now:).each { |transmit| server.receive(transmit.payload, from: CLIENT, now:) }
      server.transmits(now:).each { |transmit| client.receive(transmit.payload, from: SERVER, now:) }
      now += 0.01
    end
    now
  end

  def datagrams(connection) = [].tap { |all| connection.each_event { all << _1.data if _1.is_a?(QUIC::Event::DatagramReceived) } }

  # The client's 1-RTT packet of `frames`, given to `server`.
  def send_raw(server, *frames, now:)
    @number = (@number || 1000) + 1
    payload = QUIC::Wire::Frame.encode(frames, ack_delay_exponent: 3)
    server.receive(client_one_rtt(@keylog, dcid: @server_id, payload:, packet_number: @number), from: CLIENT, now:)
  end

  # A 1200-byte path less the short header, the connection ID, the type
  # and the Length.
  def test_the_most_a_datagram_carries
    client, = connected
    assert_equal 1200 - 21 - 8 - 1 - 2, client.datagram_max_size
    client, = connected(server_config: QUIC::Config.new(max_datagram_frame_size: 100))
    assert_equal 100 - 1 - 2, client.datagram_max_size
  end

  def test_a_datagram_each_way
    client, server, now = connected
    assert client.datagram_send("ping")
    now = exchange(client, server, now:)
    assert_equal ["ping"], datagrams(server)
    assert server.datagram_send("pong")
    exchange(client, server, now:)
    assert_equal ["pong"], datagrams(client)
  end

  # A peer that did not take them gets none; nor does one too large go.
  def test_what_does_not_go
    client, = connected(server_config: QUIC::Config.new)
    assert_nil client.datagram_max_size
    refute client.datagram_send("x")
    client, = connected
    refute client.datagram_send("x" * (client.datagram_max_size + 1))
  end

  # One past its time is dropped unsent; the rest go lowest urgency first.
  def test_expiry_and_urgency
    client, server, now = connected
    client.datagram_send("late", expires_at: now - 1)
    client.datagram_send("low", urgency: 7)
    client.datagram_send("high", urgency: 0)
    client.datagram_send("middle")
    exchange(client, server, now:)
    assert_equal %w[high middle low], datagrams(server)
  end

  # The datagrams and the streams `server` has after each datagram the
  # client sends at `now`.
  def one_by_one(client, server, now)
    client.transmits(now:).map do |transmit|
      server.receive(transmit.payload, from: CLIENT, now:)
      [datagrams(server), server.readable_streams.to_a]
    end
  end

  # A DATAGRAM goes before the streams of its urgency, stream data filling
  # the rest of the packet.
  def test_a_datagram_goes_before_streams_of_its_urgency
    client, server, now = connected
    stream_id = client.open_stream
    client.stream_write(stream_id, "x" * 5000)
    client.datagram_send("now")
    assert_equal [["now"], [stream_id]], one_by_one(client, server, now).first
  end

  # A more urgent stream goes before a DATAGRAM, which goes once the
  # stream has nothing more to send.
  def test_a_more_urgent_stream_goes_before_a_datagram
    client, server, now = connected
    stream_id = client.open_stream
    client.stream_write(stream_id, "x" * 5000)
    client.stream_priority(stream_id, urgency: 1, incremental: false)
    client.datagram_send("later", urgency: 3)
    received = one_by_one(client, server, now).map(&:first)
    assert_equal [], received.first
    assert_equal ["later"], received.flatten
    assert_operator received.index(["later"]), :>=, 4
  end

  # The application is told no when MAX_SEND_QUEUE wait, and nothing
  # waiting is dropped.
  def test_the_send_queue
    client, = connected
    QUIC::Datagrams::MAX_SEND_QUEUE.times { |index| assert client.datagram_send(index.to_s) }
    refute client.datagram_send("one more")
  end

  # Those received while MAX_RECEIVED have not been taken are dropped; the
  # connection goes on, and takes more once the application has taken
  # them.
  def test_received_while_the_application_does_not_take_them
    client, server, now = connected
    200.times do |index|
      client.datagram_send(index.to_s)
      now = exchange(client, server, now:, rounds: 1) if (index % QUIC::Datagrams::MAX_SEND_QUEUE).zero?
    end
    now = exchange(client, server, now:)
    taken = datagrams(server)
    assert_equal QUIC::Datagrams::MAX_RECEIVED, taken.size
    refute server.closed?
    client.datagram_send("after")
    exchange(client, server, now:)
    assert_equal ["after"], datagrams(server)
  end

  # A DATAGRAM frame this end did not take, or larger than it said, is
  # PROTOCOL_VIOLATION.
  def test_datagrams_not_taken
    _, server, now = connected(server_config: QUIC::Config.new)
    send_raw(server, QUIC::Wire::Frame::Datagram.new(data: "x".b), now:)
    assert_equal QUIC::ErrorCode::PROTOCOL_VIOLATION, server.close_reason&.code
    _, server, now = connected(server_config: QUIC::Config.new(max_datagram_frame_size: 100))
    send_raw(server, QUIC::Wire::Frame::Datagram.new(data: "x".b * 100), now:)
    assert_equal QUIC::ErrorCode::PROTOCOL_VIOLATION, server.close_reason&.code
  end
end
