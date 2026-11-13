require "test_helper"
require "support/quic_pair"
require "support/http3_side"

# HTTP/3 in a client's 0-RTT, joined by Raiha::Next::HTTP3Binding: HTTP/3's
# streams open at once, so the client's SETTINGS go at the beginning of the
# connection (RFC 9114 "Control Streams"), and a request goes with them
# before the handshake completes, to a server that reads it as early data.
class RaihaNextHTTP3BindingZeroRTTTest < Minitest::Test
  include NextQUICPair

  HTTP3 = Raiha::Next::HTTP3
  GET = [[":method", "GET"], [":scheme", "https"], [":authority", "localhost"], [":path", "/"]].freeze
  SEED = "\x21".b * 32
  # The second connection comes a second after the first.
  LATER = 1.0

  def tls_config = @tls_config ||= server_config(ticket_key: SEED, max_early_data_size: 1)

  def server(now: LATER, anti_replay: TLS::AntiReplay::Memory.new(now: NOW, warmup: false))
    NextHTTP3Side.new(server_connection(tls_config:, anti_replay:, now:, time: NOW + now), HTTP3::Connection.server)
  end

  # Turns both ends and passes datagrams each way, a millisecond apart.
  def exchange(client, server, now, rounds: 10)
    rounds.times do
      client.turn(now)
      client.connection.transmits(now:).each { |transmit| server.connection.receive(transmit.payload, from: CLIENT, now:) }
      server.turn(now)
      server.connection.transmits(now:).each { |transmit| client.connection.receive(transmit.payload, from: SERVER, now:) }
      now += 0.001
    end
  end

  # The ticket of a first connection, and the server's SETTINGS on it.
  def first
    client = NextHTTP3Side.new(client_connection, HTTP3::Connection.client)
    exchange(client, server(now: 0.0), 0.0, rounds: 20)
    [client.quic_events.grep(QUIC::Event::SessionTicket).first.session, client.http3.peer_settings]
  end

  def test_a_request_in_0rtt
    session, settings = first
    connection = client_connection(session:, early_data: true, now: LATER, time: NOW + LATER, random: Random.new(5))
    client = NextHTTP3Side.new(connection, HTTP3::Connection.client(remembered: settings))
    server = server()
    stream_id = nil
    client.turn(LATER) do
      stream_id = connection.open_stream
      client.http3.send_request(stream_id, GET, fin: true)
    end
    connection.transmits(now: LATER).each { |transmit| server.connection.receive(transmit.payload, from: CLIENT, now: LATER) }
    server.turn(LATER)
    refute server.connection.handshake_complete?
    assert_equal [HTTP3::Event::Settings.new(settings: HTTP3::Settings.new)], server.of(HTTP3::Event::Settings)
    assert_equal [HTTP3::Event::Headers.new(stream_id:, headers: GET, fin: true)], server.of(HTTP3::Event::Headers)
    assert server.connection.stream_early_data?(stream_id)
    exchange(client, server, LATER)
    assert_equal :accepted, connection.zero_rtt_state
    # The streams 0-RTT opened are HTTP/3's for the rest of the connection.
    [client, server].each { |side| assert_equal 1, side.of(HTTP3::Event::Settings).size }
    [client, server].each { |side| assert_empty side.quic_events.grep(QUIC::Event::Closed) }
  end

  # A server that rejects 0-RTT drops the request and the SETTINGS that
  # went in it. HTTP/3 starts over with a layer of no remembered SETTINGS,
  # whose streams open once the handshake has completed.
  def test_a_rejected_0rtt
    session, settings = first
    connection = client_connection(session:, early_data: true, now: LATER, time: NOW + LATER, random: Random.new(5))
    client = NextHTTP3Side.new(connection, HTTP3::Connection.client(remembered: settings))
    server = server(anti_replay: TLS::AntiReplay::Memory.new(now: NOW + LATER))
    client.turn(LATER) { client.http3.send_request(connection.open_stream, GET, fin: true) }
    restarted = false
    10.times do |round|
      now = LATER + (round * 0.001)
      client.turn(now) do
        next if restarted || client.quic_events.grep(QUIC::Event::ZeroRttRejected).empty?
        connection.acknowledge_zero_rtt_rejection
        client.restart(HTTP3::Connection.client)
        restarted = true
      end
      connection.transmits(now:).each { |transmit| server.connection.receive(transmit.payload, from: CLIENT, now:) }
      server.turn(now)
      server.connection.transmits(now:).each { |transmit| connection.receive(transmit.payload, from: SERVER, now:) }
    end
    assert restarted
    assert connection.handshake_complete?
    assert_empty server.of(HTTP3::Event::Headers)
    assert_equal 1, server.of(HTTP3::Event::Settings).size
    refute_nil client.http3.peer_settings
    [client, server].each { |side| assert_empty side.quic_events.grep(QUIC::Event::Closed) }
  end
end
