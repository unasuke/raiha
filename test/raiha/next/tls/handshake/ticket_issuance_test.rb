require "raiha/next/test_helper"
require "raiha/next/support/tls_pair"

# A server's NewSessionTickets (TLS API design 13.12): how many it issues
# right after the client Finished, what each holds and is bound to, and
# when it issues none, with the reason traced.
class RaihaNextTLSTicketIssuanceTest < Minitest::Test
  Pair = NextTLSPair
  TLS = Pair::TLS
  NOW = Pair::NOW

  SEED = "\x0a".b * 32
  NOW_MS = (NOW.to_r * 1000).floor

  class Recorder
    attr_reader :values

    def initialize = @values = []

    def tls_trace(value) = @values << value
  end

  def tickets(pair) = pair.server_outputs.select { |output| output.is_a?(TLS::Output::Message) && output.bytes.getbyte(0) == 4 }

  def parse(output) = TLS::Handshake.parse(output.bytes, registry: TLS::Extension::Registry::BUILTIN)

  def binding(config, resumption_binding: "", server_name: "localhost", alpn: "")
    TLS::Ticket.binding(config.ticket_binding, resumption_binding:, server_name:, alpn:)
  end

  def issued(client_config: Pair.client_config, **server_options)
    config = Pair.server_config(ticket_key: SEED, **server_options.slice(:ticket_count, :max_ticket_size, :max_early_data_size, :alpn, :client_auth))
    tracer = Recorder.new
    options = { config:, tracer:, **server_options.slice(:resumption_binding, :early_data_context, :keyring) }
    pair = Pair.run(Pair.client(config: client_config, **server_options.slice(:identities)), options)
    assert pair.client.complete? && pair.server.complete?
    [pair, config, tracer.values.grep(TLS::Trace::TicketNotIssued)]
  end

  def test_tickets_after_the_client_finished
    pair, config, refused = issued
    assert_empty refused
    assert_equal [[:secret, :application, :read], [:message, :application, 4], [:message, :application, 4]], Pair.shape(pair.server_outputs.last(3))
    first, second = tickets(pair).map { |output| parse(output) }
    assert_equal [7200, 7200], [first.ticket_lifetime, second.ticket_lifetime]
    refute_equal first.ticket_nonce, second.ticket_nonce
    refute_equal first.ticket_age_add, second.ticket_age_add
    assert_empty first.extensions
    plaintexts = [first, second].map do |nst|
      TLS::Ticket.open(nst.ticket, keys: config.ticket_keys, binding: binding(config), now: NOW, max_size: config.max_ticket_size)
    end
    assert_equal [NOW_MS, NOW_MS, 7200, 0x1301, "".b, false, nil, "".b],
      plaintexts.first.then { [_1.issued_at, _1.authenticated_at, _1.lifetime, _1.cipher_suite, _1.alpn, _1.early_data_allowed, _1.client, _1.early_data_context] }
    assert_equal first.ticket_age_add, plaintexts.first.age_add
    refute_equal plaintexts.first.psk, plaintexts.last.psk
  end

  def test_how_many_and_with_early_data
    pair, = issued(ticket_count: 3, max_early_data_size: 16_384)
    nsts = tickets(pair).map { |output| parse(output) }
    assert_equal 3, nsts.size
    assert_equal TLS::Extension::EarlyData::NST.new(max_early_data_size: 16_384), nsts.first.extension(42)
  end

  # What the layer above binds a ticket to, and the context of 0-RTT, are
  # held by the ticket.
  def test_the_binding_and_the_context
    pair, config, = issued(resumption_binding: "quic:00000001", early_data_context: "params", alpn: ["h2"], client_config: Pair.client_config(alpn: ["h2"]))
    ticket = parse(tickets(pair).first).ticket
    open = ->(bound) { TLS::Ticket.open(ticket, keys: config.ticket_keys, binding: bound, now: NOW, max_size: 8192) }
    assert_equal "params", open.(binding(config, resumption_binding: "quic:00000001", alpn: "h2")).early_data_context
    assert_equal :aead_failure, open.(binding(config, resumption_binding: "quic:00000002", alpn: "h2"))
    assert_equal :aead_failure, open.(binding(config, resumption_binding: "quic:00000001", alpn: ""))
  end

  def test_no_tickets
    # A client that does not resume lists no psk_dhe_ke.
    pair, _, refused = issued(client_config: Pair.client_config(resumption: false))
    assert_empty tickets(pair)
    assert_equal [TLS::Trace::TicketNotIssued.new(reason: :psk_mode_unsupported)], refused
    # Past what the keys seal.
    pair, _, refused = issued(max_ticket_size: 64)
    assert_empty tickets(pair)
    assert_equal [:ticket_too_large] * 2, refused.map(&:reason)
    # An authenticated client, until its tickets can be resumed.
    pair, _, refused = issued(client_auth: :required, identities: [Pair.client_identity])
    assert_empty tickets(pair)
    assert_equal [:client_auth_not_resumable], refused.map(&:reason)
    # Without keys, nothing and nothing traced.
    plain = Pair.run(Pair.client, { config: Pair.server_config, tracer: Recorder.new })
    assert_empty tickets(plain)
  end

  def test_keys_past_their_horizon
    keys = TLS::TicketKeys.ratchet(base: SEED, base_epoch: -3, origin: NOW - 10 * 3600, now: NOW - 10 * 3600, horizon: 2)
    config = Pair.server_config(ticket_keys: keys)
    tracer = Recorder.new
    pair = Pair.run(Pair.client, { config:, tracer: })
    assert_empty tickets(pair)
    assert_equal [:ticket_keys_exhausted], tracer.values.grep(TLS::Trace::TicketNotIssued).map(&:reason)
  end
end

# A client's side of the tickets (TLS API design 13.1): each becomes an
# Event::NewSessionTicket whose Session gives the PSK the server sealed in
# the ticket, unless the client does not resume.
class RaihaNextTLSTicketReceiptTest < Minitest::Test
  Pair = NextTLSPair
  TLS = Pair::TLS
  NOW = Pair::NOW
  SEED = "\x0b".b * 32

  def events(machine) = [].tap { |all| machine.each_event { all << _1 } }

  # The handshake, then the server's last outputs, its tickets, to the
  # client: Pair.run stops once both are complete.
  def handshake(client, config)
    pair = Pair.run(client, { config: })
    Pair.deliver(pair.server_outputs.select { |output| output.is_a?(TLS::Output::Message) && output.epoch == :application }, pair.client)
    pair
  end

  def test_a_session_of_each_ticket
    config = Pair.server_config(ticket_key: SEED, max_early_data_size: 1024)
    pair = handshake(Pair.client, config)
    sessions = events(pair.client).grep(TLS::Event::NewSessionTicket).map(&:session)
    assert_equal 2, sessions.size
    session = sessions.first
    now_ms = (NOW.to_r * 1000).floor
    assert_equal [0x1301, now_ms, now_ms, 7200, 1024, "localhost", nil],
      [session.cipher_suite, session.issued_at, session.authenticated_at, session.lifetime, session.max_early_data_size,
        session.server_name, session.alpn]
    assert_equal [2, Pair.ca.der, true], [session.peer_certificates.size, session.peer_certificates.last, session.peer_verified]
    binding = TLS::Ticket.binding(config.ticket_binding, resumption_binding: "", server_name: "localhost", alpn: "")
    sealed = TLS::Ticket.open(session.ticket, keys: config.ticket_keys, binding:, now: NOW, max_size: 8192)
    assert_equal sealed.psk, session.psk
    assert_equal sealed.age_add, session.age_add
    refute_equal sessions.last.psk, session.psk
  end

  def test_a_client_that_does_not_resume_ignores_tickets
    pair = handshake(Pair.client(config: Pair.client_config(resumption: false)), Pair.server_config(ticket_key: SEED))
    assert pair.client.complete?
    assert_empty events(pair.client).grep(TLS::Event::NewSessionTicket)
  end
end
