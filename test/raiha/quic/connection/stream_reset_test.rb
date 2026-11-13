require "test_helper"
require "support/quic_pair"

# Streams abandoned on either end: RESET_STREAM and STOP_SENDING, what the
# application hears, and the credit that goes back.
class RaihaNextQUICConnectionStreamResetTest < Minitest::Test
  include NextQUICPair

  def connected(server_config: QUIC::Config.new)
    client = client_connection
    server = server_connection(config: server_config)
    now = exchange(client, server, now: handshake(client, server), rounds: 3)
    [client, server].each { |connection| connection.each_event { nil } }
    [client, server, now]
  end

  def exchange(client, server, now:, rounds: 10)
    rounds.times do
      client.transmits(now:).each { |transmit| server.receive(transmit.payload, from: CLIENT, now:) }
      server.transmits(now:).each { |transmit| client.receive(transmit.payload, from: SERVER, now:) }
      now += 0.01
    end
    now
  end

  def events(connection) = [].tap { |all| connection.each_event { all << _1 } }

  # The client resets a stream it wrote 3000 bytes to: the server hears
  # with the final size, and reads the end.
  def test_a_reset
    client, server, now = connected
    stream_id = client.open_stream
    client.stream_write(stream_id, "x" * 3000)
    now = exchange(client, server, now:)
    events(server)
    client.stream_reset(stream_id, error_code: 7)
    exchange(client, server, now:)
    assert_equal [QUIC::Event::StreamReset.new(stream_id:, error_code: 7, final_size: 3000)], events(server)
    assert_nil server.stream_read(stream_id, 100)
    assert_raises(QUIC::Error::StreamError) { client.stream_write(stream_id, "more") }
  end

  # Written and reset before any of it went: the final size is 0, and the
  # connection's credit is whole again.
  def test_a_reset_before_sending
    client, server, now = connected(server_config: QUIC::Config.new(initial_max_data: 4000))
    stream_id = client.open_stream
    client.stream_write(stream_id, "x" * 3000)
    client.stream_reset(stream_id, error_code: 1)
    other = client.open_stream
    assert_equal 4000, client.stream_writable_bytes(other)
    exchange(client, server, now:)
    assert_equal [QUIC::Event::StreamReset.new(stream_id:, error_code: 1, final_size: 0)], events(server)
  end

  # The server stops reading: the client hears STOP_SENDING and resets the
  # stream with its error code.
  def test_stop_sending
    client, server, now = connected
    stream_id = client.open_stream
    client.stream_write(stream_id, "x" * 1000)
    now = exchange(client, server, now:)
    events(server)
    server.stream_stop_sending(stream_id, error_code: 9)
    exchange(client, server, now:)
    assert_equal [QUIC::Event::StopSending.new(stream_id:, error_code: 9)], events(client)
    assert_equal [QUIC::Event::StreamReset.new(stream_id:, error_code: 9, final_size: 1000)], events(server)
  end

  # What a stream stopped held goes back to the connection's window: the
  # peer can write on another stream.
  def test_credit_comes_back_from_a_stopped_stream
    client, server, now = connected(server_config: QUIC::Config.new(initial_max_data: 4000))
    first = client.open_stream
    client.stream_write(first, "x" * 4000)
    now = exchange(client, server, now:)
    second = client.open_stream
    assert_equal 0, client.stream_writable_bytes(second)
    server.stream_stop_sending(first, error_code: 0)
    exchange(client, server, now:)
    assert_operator client.stream_writable_bytes(second), :>=, 4000
  end
end
