require "test_helper"
require "support/quic_pair"

# A QUIC client's tickets: each becomes an Event::SessionTicket whose
# QUIC::Session holds the TLS session, the server's transport parameters
# that 0-RTT may use, the ALPN protocol and the version, of which the
# connection holds the newest 8 until they are taken.
class RaihaNextQUICSessionTest < Minitest::Test
  include NextQUICPair

  SEED = "\x19".b * 32

  class Recorder
    attr_reader :values

    def initialize = @values = []

    def tls_trace(value) = @values << value

    # The rest of what a connection tells its tracer is not looked at.
    def respond_to_missing?(_name, _private = false) = true

    def method_missing(name, *, **) = name == :tls_trace ? super : nil
  end

  # A handshake, then a few more round trips for the tickets.
  def exchange(client, server)
    now = handshake(client, server)
    5.times do
      server.transmits(now:).each { |transmit| client.receive(transmit.payload, from: SERVER, now:) }
      client.transmits(now:).each { |transmit| server.receive(transmit.payload, from: CLIENT, now:) }
      now += 0.001
    end
    [].tap { |all| client.each_event { all << _1 } }
  end

  def server_with_tickets(**options) = server_connection(tls_config: server_config(ticket_key: SEED, **options))

  def test_a_session_of_each_ticket
    events = exchange(client_connection, server_with_tickets)
    sessions = events.grep(QUIC::Event::SessionTicket).map(&:session)
    assert_equal 2, sessions.size
    session = sessions.first
    assert_equal ["hq-interop", QUIC::Version::V1.number], [session.alpn, session.version]
    expected = QUIC::Config.new.transport_parameters(initial_source_connection_id: "".b).remembered
    assert_equal expected, session.transport_parameters
    assert_kind_of TLS::Session, session.tls
    assert_empty events.grep(QUIC::Event::TLSEvent).select { |e| e.event.is_a?(TLS::Event::NewSessionTicket) }
  end

  def test_a_session_as_plain_values
    session = exchange(client_connection, server_with_tickets).grep(QUIC::Event::SessionTicket).first.session
    assert_equal session, QUIC::Session.from_h(session.to_h)
    bad = session.to_h.merge(transport_parameters: session.transport_parameters.to_h.merge(initial_max_data: -1))
    assert_raises(ArgumentError) { QUIC::Session.from_h(bad) }
    assert_raises(ArgumentError) { QUIC::Session.from_h(session.to_h.except(:version)) }
  end

  def connected(events) = events.grep(QUIC::Event::Connected).first.handshake

  def test_a_client_resumes
    session = exchange(client_connection, server_with_tickets).grep(QUIC::Event::SessionTicket).first.session
    client = client_connection(session:)
    server = server_with_tickets
    events = exchange(client, server)
    assert connected(events).resumed
    assert connected([].tap { |all| server.each_event { all << _1 } }).resumed
    assert_raises(ArgumentError) { client_connection(session: session.tls) }
  end

  # A server's tickets are bound to its QUIC version, and keep for 0-RTT its
  # transport parameters that a client remembers and the application's
  # part, each after its length.
  def test_what_a_server_binds_its_tickets_to
    config = server_config(ticket_key: SEED)
    server = QUIC::Connection.server(config: QUIC::Config.new, tls_config: config, keyring: server_keyring(config:), time: NOW, now: 0.0,
      app_early_data_context: "settings".b)
    session = exchange(client_connection, server).grep(QUIC::Event::SessionTicket).first.session
    open = ->(version) do
      binding = TLS::Ticket.binding(config.ticket_binding, resumption_binding: [version].pack("N"), server_name: "localhost", alpn: "hq-interop")
      TLS::Ticket.open(session.tls.ticket, keys: config.ticket_keys, binding:, now: NOW, max_size: 8192)
    end
    assert_equal :aead_failure, open.(0x6b3343cf)
    quic = QUIC::Config.new.transport_parameters(initial_source_connection_id: "".b).remembered.encode
    expected = QUIC::Wire::Writer.new.varint(quic.bytesize).bytes(quic).varint(8).bytes("settings").to_s
    assert_equal expected, open.(QUIC::Version::V1.number).early_data_context
  end

  def test_the_tickets_a_client_holds
    tracer = Recorder.new
    events = exchange(client_connection(tracer:), server_with_tickets(ticket_count: 10))
    held = events.grep(QUIC::Event::SessionTicket).map(&:session)
    assert_equal (2..9).map { |i| [i].pack("Q>") }, held.map { |s| s.tls.ticket_nonce }
    assert_equal [TLS::Trace::TicketIgnored.new(reason: :too_many_tickets)] * 2, tracer.values.grep(TLS::Trace::TicketIgnored)
  end
end
