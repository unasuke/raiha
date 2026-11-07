require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"
require "raiha/next/support/quic_recovery"

# A client's Endpoint, against a server's: what it routes to its
# connections.
class RaihaNextQUICEndpointClientTest < Minitest::Test
  include NextQUICPair

  CONFIG = QUIC::Config.new(retry_token_key: "r".b * 32, stateless_reset_key: "k".b * 32)
  SEED = "\x1b".b * 32

  def server_endpoint = QUIC::Endpoint.server(config: CONFIG, random: Random.new(3), time: NOW, now: 0.0)

  def client_endpoint = QUIC::Endpoint.client(config: QUIC::Config.new, random: Random.new(4), time: NOW, now: 0.0)

  # A connection's first Destination Connection ID comes from `random`.
  def connect(endpoint, now: 0.0, random: Random.new(1), **options)
    tls_config = client_config
    endpoint.connect(tls_config:, keyring: TLS::Keyring.client(config: tls_config, random:), server_name: "localhost", remote: SERVER,
      now:, **options)
  end

  # One TLS Config for all the server's connections, so that a ticket of
  # one resumes another, and 0-RTT is taken.
  def server_tls_config = @server_tls_config ||= server_config(ticket_key: SEED, max_early_data_size: 1)

  def anti_replay = @anti_replay ||= TLS::AntiReplay::Memory.new(now: NOW, warmup: false)

  # An application that answers an offer with a Retry when `with_retry`
  # says so and its address is not validated, and takes the others.
  def dispatch(endpoint, route, now, with_retry:)
    case route
    in QUIC::Route::Incoming(handle:, address_validated: false) if with_retry then endpoint.retry(handle, now:)
    in QUIC::Route::Incoming(handle:) then dispatch(endpoint, endpoint.admit(handle, now:), now, with_retry:)
    in QUIC::Route::ClientHello(handle:)
      tls_config = server_tls_config
      endpoint.accept(handle, tls_config:, keyring: server_keyring(config: tls_config), anti_replay:, now:)
    else nil
    end
  end

  # Passes datagrams between the two Endpoints until `connection` and a
  # connection of the server have completed the handshake; gives the
  # routes the client's Endpoint took, and the server's connection ID.
  def exchange(client, server, connection, with_retry: false, now: 0.0)
    routes = []
    server_id = nil
    20.times do
      client.each_transmit(now:) { dispatch(server, server.receive(_1.payload, from: CLIENT, to: SERVER, now:), now, with_retry:) }
      server.each_transmit(now:) do |transmit|
        header = QUIC::Wire::Packet.parse(transmit.payload, dcid_length: 8)
        server_id = header.header.scid if header.is_a?(QUIC::Wire::Packet::Parsed) && header.header.is_a?(QUIC::Wire::LongHeader)
        routes << client.receive(transmit.payload, from: SERVER, to: CLIENT, now:)
      end
      now += 0.001
    end
    [routes, server_id]
  end

  def test_a_handshake_between_endpoints
    client = client_endpoint
    server = server_endpoint
    connection = connect(client)
    routes, = exchange(client, server, connection)
    assert connection.handshake_complete?
    assert_equal [QUIC::Route::Deliver.new(connection:)], routes.uniq
    assert_equal 1, client.connection_count
  end

  # Once the handshake is confirmed, each end issues connection IDs up to
  # the other's active_connection_id_limit, with the stateless reset token
  # of its Endpoint's key, and its Endpoint brings a packet to any of them
  # to the connection.
  def test_each_end_issues_connection_ids
    client = client_endpoint
    server = server_endpoint
    tracer = NextQUICRecovery::RecordingTracer.new
    connection = connect(client, tracer:)
    exchange(client, server, connection)
    frames = ->(event) { tracer.of(event).flat_map { _1[:frames] || [] }.grep(QUIC::Wire::Frame::NewConnectionID) }
    to = ->(frame) { "\x40".b + frame.connection_id + "\0".b * 30 }

    from_server = frames.(:packet_received)
    assert_equal [[1, 0], [2, 0], [3, 0]], from_server.map { [_1.sequence_number, _1.retire_prior_to] }
    from_server.each do |frame|
      assert_equal QUIC::StatelessReset.token(key: CONFIG.stateless_reset_key, connection_id: frame.connection_id), frame.stateless_reset_token
      assert_kind_of QUIC::Route::Deliver, server.receive(to.(frame), from: CLIENT, to: SERVER, now: 1.0)
    end
    from_client = frames.(:packet_sent)
    assert_equal [1, 2, 3], from_client.map(&:sequence_number)
    from_client.each { assert_equal QUIC::Route::Deliver.new(connection:), client.receive(to.(_1), from: SERVER, to: CLIENT, now: 1.0) }
  end

  # A Retry goes to the connection it is for, which takes it.
  def test_a_retry
    client = client_endpoint
    server = server_endpoint
    connection = connect(client)
    exchange(client, server, connection, with_retry: true)
    assert connection.handshake_complete?
  end

  # A session and early_data: true go to the connection: it sends 0-RTT
  # from the first Initial, and resumes.
  def test_a_resumption
    client = client_endpoint
    server = server_endpoint
    first = connect(client)
    exchange(client, server, first)
    tickets = [].tap { |all| first.each_event { all << _1 } }.grep(QUIC::Event::SessionTicket)
    second = connect(client, now: 1.0, random: Random.new(5), session: tickets.first.session, early_data: true)
    assert_equal :pending, second.zero_rtt_state
    exchange(client, server, second, now: 1.0)
    assert second.handshake_complete?
    assert_equal :accepted, second.zero_rtt_state
  end

  # A Version Negotiation goes to the connection it is for, which abandons
  # the attempt.
  def test_a_version_negotiation
    client = client_endpoint
    connection = connect(client)
    header = nil
    client.each_transmit(now: 0.0) { header = QUIC::Wire::Packet.parse(_1.payload, dcid_length: 8).header }
    negotiation = QUIC::Wire::VersionNegotiation.new(dcid: header.scid, scid: header.dcid, versions: [0x0a0a0a0a]).encode
    assert_equal QUIC::Route::Deliver.new(connection:), client.receive(negotiation, from: SERVER, now: 0.01)
    assert connection.closed?
  end

  # A server that has lost the connection answers the client's packet with
  # a Stateless Reset, which has a connection ID of no connection of the
  # client: the client's Endpoint finds the connection by the address it
  # came from, and the connection drains.
  def test_a_stateless_reset
    client = client_endpoint
    server = server_endpoint
    connection = connect(client)
    _, server_id = exchange(client, server, connection)
    keys = QUIC::Crypto::Keys.derive(suite: TLS::CipherSuite::TLS_AES_128_GCM_SHA256, secret: "x".b * 32, version: QUIC::Version::V1)
    packet = QUIC::Wire::Packet.seal(QUIC::Wire::ShortHeader.new(dcid: server_id), packet_number: 0, packet_number_length: 1,
      payload: "\x01".b.ljust(60, "\0".b), keys:)
    reset = server_endpoint.receive(packet, from: CLIENT, to: SERVER, now: 1.0).transmit.payload
    assert_equal QUIC::Route::Deliver.new(connection:), client.receive(reset, from: SERVER, to: CLIENT, now: 1.0)
    assert connection.draining?
    assert_equal QUIC::Route::Drop.new(reason: :unknown_connection_id), client.receive(reset, from: ["192.0.2.9", 9], now: 1.0)
  end

  # A client's Endpoint takes no offers and sends no Stateless Reset.
  def test_a_client_endpoint_answers_nothing
    client = client_endpoint
    initial = client_connection(random: Random.new(7)).transmits(now: 0.0).first.payload
    assert_equal QUIC::Route::Drop.new(reason: :unknown_connection_id), client.receive(initial, from: SERVER, now: 0.0)
    keys = QUIC::Crypto::Keys.derive(suite: TLS::CipherSuite::TLS_AES_128_GCM_SHA256, secret: "x".b * 32, version: QUIC::Version::V1)
    packet = QUIC::Wire::Packet.seal(QUIC::Wire::ShortHeader.new(dcid: "c".b * 8), packet_number: 0, packet_number_length: 1,
      payload: "\x01".b.ljust(60, "\0".b), keys:)
    assert_equal QUIC::Route::Drop.new(reason: :unknown_connection_id), client.receive(packet, from: SERVER, now: 0.0)
  end

  def test_a_server_endpoint_does_not_connect
    assert_raises(QUIC::Error::Usage) { connect(server_endpoint) }
  end
end
