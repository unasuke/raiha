require "test_helper"
require "support/quic_pair"

# Streams between two Connections: opened, written as far as there is
# room, sent in turn, and sent again when lost.
class RaihaQUICConnectionStreamSendTest < Minitest::Test
  include QUICPair

  # A client and a server done with the handshake, and the time then.
  def connected(client_config: QUIC::Config.new, server_config: QUIC::Config.new)
    client = client_connection(config: client_config)
    server = server_connection(config: server_config)
    now = handshake(client, server)
    [client, server].each { |connection| connection.each_event { nil } }
    [client, server, now]
  end

  # Datagrams each way, ten milliseconds apart, `rounds` times; those of
  # the client that `drop` takes are lost. The time then.
  def exchange(client, server, now:, rounds: 10, drop: ->(_) { false })
    rounds.times do
      client.transmits(now:).each { |transmit| server.receive(transmit.payload, from: CLIENT, now:) unless drop.(transmit) }
      server.transmits(now:).each { |transmit| client.receive(transmit.payload, from: SERVER, now:) }
      now += 0.01
      [client, server].each { |connection| connection.handle_timeout(now:) if (connection.next_timeout || Float::INFINITY) <= now }
    end
    now
  end

  def events(connection) = [].tap { |all| connection.each_event { all << _1 } }

  # Everything `stream_id` has to read until it ends.
  def read_all(connection, stream_id)
    data = "".b
    while (chunk = connection.stream_read(stream_id, 1000))
      break if chunk.empty?
      data << chunk
    end
    data
  end

  def test_an_echo
    client, server, now = connected
    stream_id = client.open_stream
    assert_equal 0, stream_id
    assert_equal 5, client.stream_write(stream_id, "hello", fin: true)
    now = exchange(client, server, now:)
    assert_equal [QUIC::Event::StreamReadable.new(stream_id: 0)], events(server)
    assert_equal "hello", read_all(server, 0)
    assert_nil server.stream_read(0, 10)
    server.stream_write(0, "HELLO", fin: true)
    exchange(client, server, now:)
    assert_equal "HELLO", read_all(client, 0)
    assert_nil client.stream_read(0, 10)
  end

  # The peer's limits come with its transport parameters.
  def test_no_stream_before_the_handshake
    assert_nil client_connection.open_stream
  end

  # A unidirectional stream: the client writes, the server only reads.
  def test_a_unidirectional_stream
    client, server, now = connected
    assert_equal 2, client.open_stream(direction: :uni)
    client.stream_write(2, "one way", fin: true)
    exchange(client, server, now:)
    assert_equal "one way", read_all(server, 2)
    assert_raises(QUIC::Error::StreamError) { server.stream_write(2, "back") }
    assert_raises(QUIC::Error::StreamError) { client.stream_read(2, 10) }
  end

  # A full send buffer takes no more; as the data is acknowledged it frees,
  # and the stream written less than asked hears it can take more.
  def test_the_send_buffer
    client, server, now = connected(client_config: QUIC::Config.new(max_send_buffer: 2000))
    stream_id = client.open_stream
    assert_equal 2000, client.stream_write(stream_id, "x" * 5000)
    assert_equal 0, client.stream_writable_bytes(stream_id)
    assert_empty client.writable_streams.to_a
    exchange(client, server, now:)
    assert_equal [QUIC::Event::StreamWritable.new(stream_id:)], events(client)
    assert_equal 2000, client.stream_writable_bytes(stream_id)
    assert_equal 2000, read_all(server, stream_id).bytesize
  end

  # Streams with data to send take turns, in the first two datagrams when
  # no probe of the path MTU goes first.
  def test_streams_take_turns
    client, server, now = connected(client_config: QUIC::Config.new(enable_pmtud: false))
    first = client.open_stream
    second = client.open_stream
    client.stream_write(first, "a" * 3000)
    client.stream_write(second, "b" * 3000)
    client.transmits(now:).first(2).each { |transmit| server.receive(transmit.payload, from: CLIENT, now:) }
    assert_equal [first, second], server.readable_streams.to_a.sort
  end

  # A datagram lost on the way is sent again, and the stream arrives whole.
  def test_lost_data_goes_again
    client, server, now = connected
    stream_id = client.open_stream
    data = Random.new(1).bytes(6000)
    client.stream_write(stream_id, data, fin: true)
    sent = 0
    exchange(client, server, now:, rounds: 100, drop: ->(_) { (sent += 1) == 2 })
    assert_equal data, read_all(server, stream_id)
  end

  def test_no_writing_once_closed
    client, _, now = connected
    stream_id = client.open_stream
    client.close(now:)
    assert_raises(QUIC::Error::StateError) { client.stream_write(stream_id, "late") }
    assert_raises(QUIC::Error::StateError) { client.open_stream }
  end

  # The server allows two streams at once: when both are over on both
  # ends, MAX_STREAMS lets the client open more.
  def test_room_for_more_streams
    client, server, now = connected(server_config: QUIC::Config.new(initial_max_streams_bidi: 2))
    streams = Array.new(2) { client.open_stream }
    assert_nil client.open_stream
    streams.each { |stream_id| client.stream_write(stream_id, "ping", fin: true) }
    now = exchange(client, server, now:)
    streams.each do |stream_id|
      read_all(server, stream_id)
      server.stream_write(stream_id, "pong", fin: true)
    end
    now = exchange(client, server, now:)
    streams.each { |stream_id| assert_equal "pong", read_all(client, stream_id) }
    exchange(client, server, now:)
    assert_equal 8, client.open_stream
  end
end
