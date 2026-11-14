require "test_helper"
require "support/quic_pair"

# 0-RTT over QUIC: a client given a session and early_data: true sends what
# its streams carry before the handshake completes in 0-RTT packets, to the
# limits the session remembers, and a server that takes it reads it before
# the handshake completes.
class RaihaQUICZeroRTTTest < Minitest::Test
  include QUICPair

  SEED = "\x1a".b * 32

  def tls_config = server_config(ticket_key: SEED, max_early_data_size: 1)

  # The second connection comes a second after the first.
  LATER = 1.0

  def server(anti_replay: TLS::AntiReplay::Memory.new(now: NOW, warmup: false), now: LATER, **options)
    server_connection(tls_config:, anti_replay:, app_early_data_context: "app".b, now:, time: NOW + now, **options)
  end

  def client(**options) = client_connection(now: LATER, time: NOW + LATER, **options)

  class Recorder
    attr_reader :values

    def initialize = @values = []

    def tls_trace(value) = @values << value

    def respond_to_missing?(_name, _private = false) = true

    def method_missing(name, *, **) = name == :tls_trace ? super : nil
  end

  def events(connection) = [].tap { |all| connection.each_event { all << _1 } }

  # A handshake, then a few more round trips for what follows it.
  def exchange(client, server, now: 0.0)
    now = handshake(client, server, now:)
    5.times do
      server.transmits(now:).each { |transmit| client.receive(transmit.payload, from: SERVER, now:) }
      client.transmits(now:).each { |transmit| server.receive(transmit.payload, from: CLIENT, now:) }
      now += 0.001
    end
    now
  end

  def session
    @session ||= begin
      client = client_connection
      exchange(client, server(now: 0.0))
      events(client).grep(QUIC::Event::SessionTicket).first.session
    end
  end

  def test_a_client_sends_0rtt_a_server_takes
    client = client(session:, early_data: true)
    assert_equal :pending, client.zero_rtt_state
    stream = client.open_stream
    client.stream_write(stream, "early", fin: true)
    server = server()
    client.transmits(now: LATER).each { |transmit| server.receive(transmit.payload, from: CLIENT, now: LATER) }
    refute server.handshake_complete?
    assert_equal "early", server.stream_read(stream, 100)
    assert server.stream_early_data?(stream)
    exchange(client, server, now: LATER)
    assert_equal :accepted, client.zero_rtt_state
    assert events(server).grep(QUIC::Event::Connected).first.handshake.early_data_accepted
    # A stream after the handshake came in 1-RTT, and a client marks none.
    later = client.open_stream
    client.stream_write(later, "late", fin: true)
    exchange(client, server, now: LATER + 0.1)
    assert_equal "late", server.stream_read(later, 100)
    refute server.stream_early_data?(later)
    refute client.stream_early_data?(stream)
  end

  # With an initial window of twenty datagrams, a client in 0-RTT, with no
  # RTT sample yet and so no pacing, sends its Initial and 0-RTT packets to
  # no more than RFC 9002's initial window, ten datagrams; Rapid Start or
  # not.
  def test_0rtt_waits_for_an_rtt_sample_to_go_past_rfc_9002s_initial_window
    initial_window = Ractor.shareable_lambda { |max_datagram_size| 20 * max_datagram_size }
    [nil, QUIC::Congestion::Startup::RapidStart].each do |startup|
      client = client(session:, early_data: true, config: QUIC::Config.new(startup:, initial_window:))
      stream = client.open_stream
      client.stream_write(stream, "x" * 100_000, fin: true)
      sent = client.transmits(now: LATER).sum { _1.payload.bytesize }
      assert_operator sent, :>, 10_000
      assert_operator sent, :<=, QUIC::Config::DEFAULT_INITIAL_WINDOW.call(1200)
    end
  end

  # A Retry gives the client its first RTT sample, but no ACK has told the
  # congestion controller of it, and so nothing is paced yet: what goes
  # again after the Retry keeps to RFC 9002's initial window all the same.
  def test_0rtt_after_a_retry_keeps_to_rfc_9002s_initial_window
    initial_window = Ractor.shareable_lambda { |max_datagram_size| 20 * max_datagram_size }
    [nil, QUIC::Congestion::Startup::RapidStart].each do |startup|
      endpoint = QUIC::Endpoint.server(config: QUIC::Config.new, random: Random.new(3), time: NOW + LATER, now: LATER)
      client = client(session:, early_data: true, config: QUIC::Config.new(startup:, initial_window:))
      stream = client.open_stream
      client.stream_write(stream, "x" * 100_000, fin: true)
      client.transmits(now: LATER).each do |transmit|
        route = endpoint.receive(transmit.payload, from: CLIENT, to: SERVER, now: LATER)
        endpoint.retry(route.handle, now: LATER) if route in QUIC::Route::Incoming(address_validated: false)
      end
      endpoint.each_transmit(now: LATER + 0.01) { client.receive(_1.payload, from: SERVER, now: LATER + 0.01) }
      assert client.stats.rtt < QUIC::Recovery::INITIAL_RTT, "the Retry gave an RTT sample"
      sent = client.transmits(now: LATER + 0.01).sum { _1.payload.bytesize }
      assert_operator sent, :>, 10_000
      assert_operator sent, :<=, QUIC::Config::DEFAULT_INITIAL_WINDOW.call(1200)
    end
  end

  # Without early_data: true, or with a session of another version, the
  # data waits for 1-RTT.
  def test_no_0rtt_unless_asked
    assert_equal :disabled, client(session:).zero_rtt_state
    assert_equal :disabled, client(session: session.with(version: 0x6b3343cf), early_data: true).zero_rtt_state
    assert_equal :disabled, client(early_data: true).zero_rtt_state
    client = client(session:)
    server = server()
    client.transmits(now: LATER).each { |transmit| server.receive(transmit.payload, from: CLIENT, now: LATER) }
    assert_empty server.readable_streams.to_a
  end

  # A rejected 0-RTT rolls the client back (RFC 9001 "Accepting and
  # Rejecting 0-RTT"): its streams are gone and nothing of them goes again;
  # until it says it knows, its streams and open_stream raise; then IDs
  # start over from 0.
  def test_a_client_rolled_back
    client = client(session:, early_data: true)
    stream = client.open_stream
    client.stream_write(stream, "early", fin: true)
    server = server(app_early_data_context: "other".b)
    exchange(client, server, now: LATER)
    assert client.handshake_complete?
    assert_equal [QUIC::Event::ZeroRttRejected.new(reason: :rejected_by_server)], events(client).grep(QUIC::Event::ZeroRttRejected)
    assert_raises(QUIC::Error::ZeroRttRejected) { client.open_stream }
    assert_raises(QUIC::Error::ZeroRttRejected) { client.stream_write(stream, "again") }
    assert_empty server.readable_streams.to_a
    client.acknowledge_zero_rtt_rejection
    assert_equal stream, client.open_stream
    client.stream_write(stream, "again", fin: true)
    exchange(client, server, now: LATER + 0.1)
    assert_equal "again", server.stream_read(stream, 100)
    refute server.stream_early_data?(stream)
  end

  # A server that took 0-RTT may not lower the limits it used (RFC 9000
  # "Values of Transport Parameters for 0-RTT"); its transport parameters,
  # which come with EncryptedExtensions, are checked against the session's.
  def test_limits_a_server_that_took_0rtt_lowers
    lowered = { initial_max_data: 1, initial_max_streams_bidi: 1, initial_max_stream_data_uni: 1 }
    lowered.each do |name, value|
      client, parameters = client_at_the_server_initial
      error = assert_raises(QUIC::Violation, name.to_s) { client.peer_transport_parameters(parameters.with(name => value).encode) }
      assert_equal QUIC::ErrorCode::PROTOCOL_VIOLATION, error.code
      assert_includes error.message, name.to_s
    end
    client, parameters = client_at_the_server_initial
    client.peer_transport_parameters(parameters.with(initial_max_data: parameters.initial_max_data * 2).encode)
  end

  # A client sending 0-RTT that has taken the server's Initial and nothing
  # after, and transport parameters with the connection IDs it expects.
  def client_at_the_server_initial
    client = client(session:, early_data: true)
    sent = client.transmits(now: LATER)
    odcid = QUIC::Wire::Packet.parse(sent.first.payload, dcid_length: 8).header.dcid
    server = server()
    sent.each { |transmit| server.receive(transmit.payload, from: CLIENT, now: LATER) }
    datagram = server.transmits(now: LATER).first.payload
    initial = QUIC::Wire::Packet.parse(datagram, dcid_length: 8)
    client.receive(datagram.byteslice(0, initial.end_offset), from: SERVER, now: LATER)
    [client, QUIC::Config.new.transport_parameters(initial_source_connection_id: initial.header.scid, original_destination_connection_id: odcid)]
  end

  # A Retry is no rejection of 0-RTT (RFC 9001 "Accepting and Rejecting
  # 0-RTT"): the client sends it again after the Initial with the Retry's
  # token, and the server takes it.
  def test_0rtt_across_a_retry
    endpoint = QUIC::Endpoint.server(config: QUIC::Config.new, random: Random.new(3), time: NOW + LATER, now: LATER)
    anti_replay = TLS::AntiReplay::Memory.new(now: NOW, warmup: false)
    accepted = nil
    dispatch = lambda do |route, now|
      case route
      in QUIC::Route::Incoming(handle:, address_validated: false) then endpoint.retry(handle, now:)
      in QUIC::Route::Incoming(handle:) then dispatch.(endpoint.admit(handle, now:), now)
      in QUIC::Route::ClientHello(handle:)
        config = tls_config
        accepted = endpoint.accept(handle, tls_config: config, keyring: server_keyring(config:), now:, anti_replay:,
          app_early_data_context: "app".b)
      else nil
      end
    end
    client = client(session:, early_data: true)
    stream = client.open_stream
    client.stream_write(stream, "early", fin: true)
    now = LATER
    40.times do
      break if client.handshake_complete? && accepted&.handshake_complete?
      client.transmits(now:).each { dispatch.(endpoint.receive(_1.payload, from: CLIENT, to: SERVER, now:), now) }
      endpoint.each_transmit(now:) { client.receive(_1.payload, from: SERVER, now:) }
      now += 0.001
    end
    assert_equal :accepted, client.zero_rtt_state
    assert_equal "early", accepted.stream_read(stream, 100)
    assert accepted.stream_early_data?(stream)
  end

  # A server that takes no 0-RTT: the client learns it, and sends no more
  # 0-RTT packets.
  def test_0rtt_a_server_does_not_take
    client = client(session:, early_data: true)
    tracer = Recorder.new
    exchange(client, server(app_early_data_context: "other".b, tracer:), now: LATER)
    assert_equal :rejected, client.zero_rtt_state
    assert_equal [:early_data_context_mismatch], tracer.values.grep(TLS::Trace::EarlyDataRejected).map(&:reason)
    refute_includes client.transmits(now: LATER + 1).map { |t| QUIC::Wire::Packet.parse(t.payload, dcid_length: 8).header.type }, :zero_rtt
  end
end
