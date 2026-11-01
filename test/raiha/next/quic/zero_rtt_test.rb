require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# 0-RTT over QUIC: a client given a session and early_data: true sends what
# its streams carry before the handshake completes in 0-RTT packets, to the
# limits the session remembers, and a server that takes it reads it before
# the handshake completes.
class RaihaNextQUICZeroRTTTest < Minitest::Test
  include NextQUICPair

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
    exchange(client, server, now: LATER)
    assert_equal :accepted, client.zero_rtt_state
    assert events(server).grep(QUIC::Event::Connected).first.handshake.early_data_accepted
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
