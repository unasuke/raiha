require "raiha/next/test_helper"
require "raiha/next/support/quic_transfer"
require "raiha/next/support/http3_side"

# HTTP/3 over QUIC joined by Raiha::Next::HTTP3Binding: a request and its
# response, HTTP Datagrams and a stream left unread on a Test::Network; a
# reset that comes with the stream's data; and a peer that does not allow
# HTTP/3 its streams.
class RaihaNextHTTP3BindingTest < Minitest::Test
  include NextQUICTransfer

  HTTP3 = Raiha::Next::HTTP3
  GET = [[":method", "GET"], [":scheme", "https"], [":authority", "localhost"], [":path", "/"]].freeze
  POST = [[":method", "POST"], [":scheme", "https"], [":authority", "localhost"], [":path", "/upload"]].freeze
  CONNECT = [[":method", "CONNECT"], [":protocol", "echo"], [":scheme", "https"], [":authority", "localhost"], [":path", "/echo"]].freeze
  OK = [[":status", "200"]].freeze

  # A network of a client and a server, each with a Side made once it has
  # a connection, of HTTP/3 `settings`, the server's given
  # `on_server_event`. Gives the network, the client's QUIC connection and
  # the Sides by :client and :server.
  def h3_network(on_server_event: nil, settings: HTTP3::Settings.new, **options)
    sides = {}
    client_step = ->(connection, now) { (sides[:client] ||= NextHTTP3Side.new(connection, HTTP3::Connection.client(settings:))).turn(now) }
    server_step = lambda do |endpoint, now|
      connection = endpoint.connections.first or next
      sides[:server] ||= NextHTTP3Side.new(connection, HTTP3::Connection.server(settings: settings.with(enable_connect_protocol: true)))
      sides[:server].turn(now, on_server_event)
    end
    net, client, = transfer_network(client_step:, server_step:, **options)
    [net, client, sides]
  end

  # The server writes a response as fast as HTTP/3 takes it, waiting for
  # Event::Writable, and the client reads it. Both ends hear the other's
  # SETTINGS; the client's application hears QUIC's Event::Connected, which
  # the binding passes on, and none of the events it takes.
  def test_a_get_and_its_response
    body = Random.new(3).bytes(200_000)
    left = {}
    respond = lambda do |side, event|
      case event
      when HTTP3::Event::Headers
        side.http3.send_headers(event.stream_id, OK)
        left[event.stream_id] = body
      when HTTP3::Event::Writable then nil
      else next
      end
      rest = left.fetch(event.stream_id)
      left[event.stream_id] = rest.byteslice(side.http3.send_data(event.stream_id, rest, fin: true)..)
    end
    net, quic, sides = h3_network(on_server_event: respond)
    assert net.run_until { quic.handshake_complete? }
    client = sides.fetch(:client)
    client.http3.send_request(quic.open_stream, GET, fin: true)
    assert net.run_until { client.of(HTTP3::Event::Data).last&.fin }
    server = sides.fetch(:server)
    assert_equal [HTTP3::Event::Headers.new(stream_id: 0, headers: GET, fin: true)], server.of(HTTP3::Event::Headers)
    assert_equal [HTTP3::Event::Headers.new(stream_id: 0, headers: OK, fin: false)], client.of(HTTP3::Event::Headers)
    assert_equal body, client.of(HTTP3::Event::Data).sum("".b, &:data)
    refute_empty server.of(HTTP3::Event::Writable)
    [client, server].each { |side| assert_equal 1, side.of(HTTP3::Event::Settings).size }
    assert_includes client.quic_events.map(&:class), QUIC::Event::Connected
    assert_empty client.quic_events.map(&:class) & Raiha::Next::HTTP3Binding::HTTP3_EVENTS
  end

  # The HTTP Datagrams of an Extended CONNECT request go both ways in
  # QUIC's DATAGRAM frames, the server echoing the client's, where both
  # ends take them in QUIC and in HTTP/3.
  def test_http_datagrams
    config = QUIC::Config.new(max_datagram_frame_size: 1200)
    respond = lambda do |side, event|
      case event
      when HTTP3::Event::Headers then side.http3.send_headers(event.stream_id, OK)
      when HTTP3::Event::Datagram then side.http3.datagram_send(event.stream_id, event.payload)
      end
    end
    net, quic, sides = h3_network(on_server_event: respond, settings: HTTP3::Settings.new(h3_datagram: true), client_config: config, server_config: config)
    assert net.run_until { sides[:client]&.http3&.peer_settings }
    client = sides.fetch(:client)
    client.http3.send_request(quic.open_stream, CONNECT)
    assert net.run_until { client.of(HTTP3::Event::Headers).any? }
    assert client.http3.datagram_send(0, "ping")
    assert net.run_until { client.of(HTTP3::Event::Datagram).any? }
    assert_equal [HTTP3::Event::Datagram.new(stream_id: 0, payload: "ping")], client.of(HTTP3::Event::Datagram)
  end

  # A stream paused is left unread, the peer held back by QUIC's flow
  # control, until it is resumed.
  def test_a_paused_stream
    pause = ->(side, event) { side.binding.pause(event.stream_id) if event.is_a?(HTTP3::Event::Headers) }
    net, quic, sides = h3_network(on_server_event: pause)
    assert net.run_until { quic.handshake_complete? }
    client = sides.fetch(:client)
    client.http3.send_request(quic.open_stream, POST)
    assert net.run_until { sides[:server]&.of(HTTP3::Event::Headers)&.any? }
    server = sides.fetch(:server)
    client.http3.send_data(0, "abc", fin: true)
    net.advance(1.0)
    assert_empty server.of(HTTP3::Event::Data)
    server.binding.resume(0)
    assert net.run_until { server.of(HTTP3::Event::Data).any? }
    assert_equal [HTTP3::Event::Data.new(stream_id: 0, data: "abc", fin: true)], server.of(HTTP3::Event::Data)
  end

  # Data and the RESET_STREAM after it taken by the server in one go: the
  # stream reads as ended, but HTTP/3 has heard of the reset by then, so
  # the request is reset rather than over.
  def test_data_and_a_reset_taken_together
    client_quic = client_connection
    server_quic = server_connection
    now = handshake(client_quic, server_quic)
    client = NextHTTP3Side.new(client_quic, HTTP3::Connection.client)
    server = NextHTTP3Side.new(server_quic, HTTP3::Connection.server)
    stream_id = client_quic.open_stream
    client.turn(now) { client.http3.send_request(stream_id, POST) }
    deliver(client_quic, server_quic, now)
    server.turn(now)
    assert_equal 1, server.of(HTTP3::Event::Headers).size
    client.turn(now) { client.http3.send_data(stream_id, "abc") }
    deliver(client_quic, server_quic, now)
    client.turn(now) { client.http3.cancel(stream_id) }
    deliver(client_quic, server_quic, now)
    server.turn(now)
    assert_equal [HTTP3::Event::Reset.new(stream_id:, error_code: HTTP3::ErrorCode::REQUEST_CANCELLED)], server.of(HTTP3::Event::Reset)
    assert_empty server.of(HTTP3::Event::Data)
  end

  # RFC 9114 "Unidirectional Streams": a peer must allow three streams
  # going one way; the client closes the connection with
  # H3_GENERAL_PROTOCOL_ERROR when it allows two.
  def test_fewer_than_three_streams_allowed
    net, quic, sides = h3_network(server_config: QUIC::Config.new(initial_max_streams_uni: 2))
    assert net.run_until { quic.close_reason }
    assert_equal HTTP3::ErrorCode::GENERAL_PROTOCOL_ERROR, quic.close_reason.code
    assert(quic.close_reason.application)
    assert_kind_of QUIC::Event::Closed, sides.fetch(:client).quic_events.last
  end

  # What `from` sends goes to `to` at `now`.
  private def deliver(from, to, now)
    from.transmits(now:).each { |transmit| to.receive(transmit.payload, from: CLIENT, now:) }
  end
end
