require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# RFC 9000 "Connection Termination", as 250 "Closing" applies it.
class RaihaNextQUICConnectionCloseTest < Minitest::Test
  include NextQUICPair

  def events(connection) = [].tap { |events| connection.each_event { events << _1 } }

  def closed(connection) = events(connection).grep(QUIC::Event::Closed)

  def deliver(from, to, now:, address: from.role == :client ? CLIENT : SERVER)
    from.transmits(now:).each { |transmit| to.receive(transmit.payload, from: address, now:) }
  end

  def connected
    client = client_connection
    server = server_connection
    now = handshake(client, server)
    events(client)
    events(server)
    [client, server, now]
  end

  # The application closes: the peer drains with its error, and both are
  # closed three PTOs on. With the handshake confirmed, the frame goes in a
  # 1-RTT packet alone.
  def test_an_application_closes
    client, server, now = connected
    client.close(error_code: 7, reason: "bye", now:)
    assert client.closing?
    assert_equal [QUIC::ConnectionError.new(code: 7, frame_type: nil, reason: "bye", application: true)], closed(client).map(&:error)
    deliver(client, server, now:)
    assert server.draining?
    assert_equal [[7, "bye", true, true]], closed(server).map { [_1.error.code, _1.error.reason, _1.error.application, _1.by_peer] }
    assert_empty server.transmits(now:)
    [client, server].each do |connection|
      connection.handle_timeout(now: connection.next_timeout)
      assert connection.closed?
      assert_nil connection.next_timeout
    end
  end

  # While closing, what comes is answered with the CONNECTION_CLOSE frame
  # again: the first, second and fourth datagram, not the third.
  def test_closing_answers_less_and_less
    client, server, now = connected
    client.close(now:)
    assert_equal 1, client.transmits(now:).size
    answered = 4.times.map do
      client.receive("\x40".b + "x".b * 40, from: SERVER, now:)
      client.transmits(now:).size
    end
    assert_equal [1, 1, 0, 1], answered
  end

  # Before the handshake, an application's error goes in an Initial packet
  # as APPLICATION_ERROR, with no reason, in a padded datagram.
  def test_closing_during_the_handshake
    client = client_connection
    server = server_connection
    deliver(client, server, now: 0.0)
    events(server)
    client.close(error_code: 7, reason: "secret", now: 0.0)
    transmits = client.transmits(now: 0.0)
    assert_equal [1200], transmits.map { _1.payload.bytesize }
    server.receive(transmits.first.payload, from: CLIENT, now: 0.0)
    assert_equal [[QUIC::ErrorCode::APPLICATION_ERROR, "", false]], closed(server).map { [_1.error.code, _1.error.reason, _1.error.application] }
  end

  # RFC 9000 "Idle Timeout": the smaller of the two, gone quietly.
  def test_idle_timeout
    client, _server, now = connected
    client.handle_timeout(now: now + 29.9)
    refute client.closed?
    client.handle_timeout(now: now + 30.0)
    assert client.closed?
    assert_equal ["idle timeout"], closed(client).map { _1.error.reason }
    assert_empty client.transmits(now: now + 30.0)
    short = client_connection(config: QUIC::Config.new(max_idle_timeout: 5.0))
    other = server_connection
    now = handshake(short, other)
    other.handle_timeout(now: now + 4.9)
    refute other.closed?
    other.handle_timeout(now: now + 5.0)
    assert other.closed?
  end

  # TLS fails on the server: no ALPN in common closes with CRYPTO_ERROR
  # 0x178, which the client drains with.
  def test_tls_failure_closes
    client = client_connection
    server = server_connection(tls_config: server_config(alpn: ["h3"]))
    deliver(client, server, now: 0.0)
    assert server.closing?
    deliver(server, client, now: 0.0)
    assert client.draining?
    assert_equal [[0x178, false, true]], closed(client).map { [_1.error.code, _1.error.application, _1.by_peer] }
  end

  # A packet received again restarts no idle timeout: one captured and
  # sent over and over does not keep a connection whose peer has gone.
  def test_a_duplicate_restarts_no_idle_timeout
    client = client_connection
    server = server_connection
    sent = []
    now = 0.0
    20.times do
      break if client.handshake_complete? && server.handshake_complete?
      client.transmits(now:).each do |transmit|
        sent << transmit.payload
        server.receive(transmit.payload, from: CLIENT, now:)
      end
      server.transmits(now:).each { |transmit| client.receive(transmit.payload, from: SERVER, now:) }
      now += 0.001
    end
    server.receive(sent.last, from: CLIENT, now: now + 29.0)
    server.handle_timeout(now: now + 30.5)
    assert server.closed?
  end
end
