require "raiha/next/test_helper"
require "raiha/next/support/tls_pair"

# A server resuming with a ticket it issued: the first identity whose ticket
# opens and passes the checks against the current Config, its binder
# verified, and a handshake without certificates; any other identity is
# passed over with its reason traced, and a full handshake follows.
class RaihaNextTLSResumptionTest < Minitest::Test
  Pair = NextTLSPair
  TLS = Pair::TLS
  NOW = Pair::NOW
  SEED = "\x0d".b * 32
  DAY = 86_400
  REGISTRY = TLS::Extension::Registry::BUILTIN

  class Recorder
    attr_reader :values

    def initialize = @values = []

    def tls_trace(value) = @values << value
  end

  def events(machine) = [].tap { |all| machine.each_event { all << _1 } }

  def ms(time) = (time.to_r * 1000).floor

  def server_config(**options) = Pair.server_config(ticket_key: SEED, **options)

  # The handshake, then the server's tickets to the client, which Pair.run
  # stops before.
  def handshake(client, server_options, now: NOW)
    pair = Pair.run(client, server_options, now:)
    Pair.deliver(pair.server_outputs.select { |output| output.is_a?(TLS::Output::Message) && output.epoch == :application }, pair.client, now:)
    pair
  end

  def sessions(machine) = events(machine).grep(TLS::Event::NewSessionTicket).map(&:session)

  # A session from a full handshake at NOW.
  def session(config: server_config) = sessions(handshake(Pair.client, { config: }).client).first

  def completion(machine) = events(machine).grep(TLS::Event::HandshakeComplete).first

  def test_a_server_resumes_with_its_ticket
    session = self.session
    later = NOW + 60
    tracer = Recorder.new
    pair = handshake(Pair.client(session:, now: later), { config: server_config, tracer: }, now: later)
    client, server = completion(pair.client), completion(pair.server)
    assert client.resumed && server.resumed
    assert_equal session.peer_certificates, client.peer_certificates.map(&:to_der)
    assert client.peer_verified
    assert_equal [], server.peer_certificates
    handshake_messages = pair.server_outputs.grep(TLS::Output::Message).select { |output| output.epoch == :handshake }
    assert_equal [TLS::Handshake::EncryptedExtensions::MSG_TYPE, TLS::Handshake::Finished::MSG_TYPE],
      handshake_messages.map { |output| output.bytes.getbyte(0) }
    assert_equal [TLS::Trace::BinderVerified.new(index: 0)], tracer.values.grep(TLS::Trace::BinderVerified)
    assert_empty tracer.values.grep(TLS::Trace::PskRejected)
  end

  # The tickets of a resumed connection carry the time of the full
  # handshake on, on both sides.
  def test_tickets_of_a_resumed_connection_keep_the_full_handshake_time
    later = NOW + 60
    renewed = sessions(handshake(Pair.client(session:, now: later), { config: server_config }, now: later).client)
    assert_equal 2, renewed.size
    assert_equal [[ms(later), ms(NOW)]] * 2, renewed.map { |s| [s.issued_at, s.authenticated_at] }
    binding = TLS::Ticket.binding(server_config.ticket_binding, resumption_binding: "", server_name: "localhost", alpn: "")
    sealed = TLS::Ticket.open(renewed.first.ticket, keys: server_config.ticket_keys, binding:, now: later, max_size: 8192)
    assert_equal ms(NOW), sealed.authenticated_at
  end

  # The reasons each identity is passed over for, a full handshake
  # following.
  def passed_over(config, now: NOW + 60, session: self.session, keyring: nil)
    tracer = Recorder.new
    pair = Pair.run(Pair.client(session:, now:), { config:, keyring:, tracer: }, now:)
    refute completion(pair.server)&.resumed
    tracer.values.grep(TLS::Trace::PskRejected).map { |rejected| [rejected.index, rejected.reason] }
  end

  def test_tickets_passed_over
    session = self.session
    {
      unknown_key: server_config(ticket_key: "\x0e".b * 32),
      aead_failure: server_config(resumption_scope: "another tenant"),
      ticket_expired: server_config(ticket_lifetime: 30),
      cipher_suite_hash_mismatch: server_config(cipher_suites: %i[TLS_AES_256_GCM_SHA384]),
      client_certificate_missing: server_config(client_auth: :required)
    }.each do |reason, config|
      assert_equal [[0, reason]], passed_over(config, session:), reason
    end
  end

  def client_auth_config(**options) = server_config(client_auth: :required, **options)

  # A session from a full handshake at NOW with a client certificate, and
  # the leaf the server verified.
  def authenticated_session(identity: Pair.client_identity)
    pair = handshake(Pair.client(identities: [identity]), { config: client_auth_config })
    [sessions(pair.client).first, completion(pair.server).peer_certificates.first]
  end

  # The server takes the client's certificate from the ticket, the leaf
  # alone, and asks for none.
  def test_a_server_resumes_an_authenticated_client
    session, leaf = authenticated_session
    later = NOW + 60
    pair = handshake(Pair.client(session:, now: later), { config: client_auth_config }, now: later)
    server = completion(pair.server)
    assert server.resumed
    assert_equal [leaf.to_der], server.peer_certificates.map(&:to_der)
    assert server.peer_verified
    refute_includes pair.server_outputs.grep(TLS::Output::Message).map { |output| output.bytes.getbyte(0) },
      TLS::Handshake::CertificateRequest::MSG_TYPE
    # The tickets of the resumed connection keep what the first one did.
    keys = client_auth_config.ticket_keys
    binding = TLS::Ticket.binding(client_auth_config.ticket_binding, resumption_binding: "", server_name: "localhost", alpn: "")
    first, renewed = [session, sessions(pair.client).first].map do |s|
      TLS::Ticket.open(s.ticket, keys:, binding:, now: later, max_size: 8192).client
    end
    assert_equal first, renewed
  end

  # A Verifier that accepts what `inner` does but cannot say what its rules
  # are.
  class Unsayable
    def initialize(inner) = @inner = inner

    def verify(**) = @inner.verify(**)

    def resumption_policy = nil
  end

  def test_client_certificate_tickets_passed_over
    session, = authenticated_session
    store = TLS::Verifier::Default.store([Pair.ca.der])
    {
      client_auth_disabled: [server_config, nil],
      client_auth_not_resumable: [client_auth_config, ->(config) { Unsayable.new(TLS::Verifier::Default.new(store:)) }],
      verification_rules_changed:
        [client_auth_config, ->(config) { TLS::Verifier::Default.new(store:, verify_flags: OpenSSL::X509::V_FLAG_PARTIAL_CHAIN) }],
      trust_anchor_removed: [client_auth_config(trust_anchors: [Pair::PKI.ca(name: "Another CA").der]), nil]
    }.each do |reason, (config, verifier)|
      keyring = verifier && Pair.server_keyring(config:, verifier: verifier.call(config))
      assert_equal [[0, reason]], passed_over(config, session:, keyring:), reason
    end
  end

  # The chain's dates are checked again: past the leaf's, or past those of
  # the CA that issued it, the leaf's own still good.
  def test_a_ticket_of_a_client_certificate_past_its_dates
    leaf = Pair::PKI.leaf(Pair.ca, names: [], common_name: "client", key: Pair::PKI.key(:client), purpose: "clientAuth", serial: 5,
      not_after: NOW + 120)
    session, = authenticated_session(identity: TLS::Keyring::Identity.new(cert_der: [leaf.der, Pair.ca.der], key_der: leaf.key_der))
    assert_equal [[0, :client_certificate_expired]], passed_over(client_auth_config, now: NOW + 180, session:)

    short = Pair::PKI.ca(name: "Short-lived CA", key: Pair::PKI.key(:short_lived_ca), not_after: NOW + 120)
    leaf = Pair::PKI.leaf(short, names: [], common_name: "client", key: Pair::PKI.key(:client), purpose: "clientAuth", serial: 7)
    config = client_auth_config(trust_anchors: [Pair.ca.der, short.der])
    identity = TLS::Keyring::Identity.new(cert_der: [leaf.der, short.der], key_der: leaf.key_der)
    session = sessions(handshake(Pair.client(identities: [identity]), { config: }).client).first
    assert_equal [[0, :client_certificate_expired]], passed_over(config, now: NOW + 180, session:)
  end

  # A chain that ended at no anchor is never trusted again; one that
  # Verifier::None took ended at none, even when the client put a trusted
  # anchor last.
  def test_a_ticket_of_a_chain_that_ended_at_no_anchor
    leaf = Pair::PKI.leaf(Pair.ca, names: [], common_name: "client", key: Pair::PKI.key(:client), purpose: "clientAuth", serial: 6)
    config = client_auth_config
    [[leaf.der], [leaf.der, Pair.ca.der]].each do |chain|
      identity = TLS::Keyring::Identity.new(cert_der: chain, key_der: leaf.key_der)
      keyring = Pair.server_keyring(config:, verifier: TLS::Verifier::None.new)
      pair = handshake(Pair.client(identities: [identity]), { config:, keyring: })
      session = sessions(pair.client).first
      later_keyring = Pair.server_keyring(config:, verifier: TLS::Verifier::None.new)
      assert_equal [[0, :trust_anchor_removed]], passed_over(config, session:, keyring: later_keyring), chain.size
    end
  end

  # A ticket is bound to the server name and ALPN protocol of the
  # connection it came on: another name or protocol passes it over as a
  # forgery would be.
  def test_the_name_and_protocol_a_ticket_is_bound_to
    h2 = Pair.client_config(alpn: %w[h2 http/1.1])
    session = sessions(handshake(Pair.client(config: h2), { config: server_config(alpn: ["h2"]) }).client).first
    assert_equal "h2", session.alpn
    assert_equal [[0, :aead_failure]], passed_over(server_config(alpn: ["http/1.1"]), session:)
  end

  # The client's own clock lets the session go; the ticket keeps the time
  # of the full handshake 7 days ago.
  def test_a_ticket_of_key_material_past_7_days
    config = server_config(ticket_lifetime: 604_800)
    renewed = sessions(handshake(Pair.client(session: session(config:), now: NOW + 6 * DAY), { config: }, now: NOW + 6 * DAY).client).first
    now = NOW + 7 * DAY + 60
    assert_equal [[0, :authentication_expired]], passed_over(config, now:, session: renewed.with(authenticated_at: ms(now)))
  end

  # A client Finished that comes past the 7 days gets no ticket.
  def test_no_ticket_past_7_days
    config = server_config(ticket_lifetime: 604_800)
    renewed = sessions(handshake(Pair.client(session: session(config:), now: NOW + 6 * DAY), { config: }, now: NOW + 6 * DAY).client).first
    before, after = NOW + 7 * DAY - 10, NOW + 7 * DAY + 10
    client = Pair.client(session: renewed, now: before)
    tracer = Recorder.new
    server = Pair.server(client.outputs.first.bytes, config:, tracer:, now: before)
    Pair.deliver(server.outputs, client, now: before)
    Pair.deliver(client.outputs, server, now: after)
    assert completion(server).resumed
    assert_equal [:authentication_expired], tracer.values.grep(TLS::Trace::TicketNotIssued).map(&:reason)
  end

  def offered_client_hello(session = self.session)
    TLS::Handshake.parse(Pair.client(session:).outputs.first.bytes, registry: REGISTRY)
  end

  def serve(ch, tracer: Recorder.new)
    Pair.server(ch.encode, config: server_config, tracer:)
  end

  def failure(machine) = events(machine).grep(TLS::Event::Failed).first&.then { |f| [f.alert, f.reason] }

  # With psk_ke alone no ticket is opened, and a client that can do a full
  # handshake gets one.
  def test_a_client_hello_without_psk_dhe_ke
    ch = offered_client_hello
    psk_ke = TLS::Extension::PskKeyExchangeModes.new(ke_modes: [0])
    ch = ch.with(extensions: ch.extensions.map { |ext| ext.extension_type == TLS::Extension::PskKeyExchangeModes::TYPE ? psk_ke : ext })
    tracer = Recorder.new
    server = serve(ch, tracer:)
    refute server.failed?
    assert_equal [[0, :psk_mode_unsupported]], tracer.values.grep(TLS::Trace::PskRejected).map { |r| [r.index, r.reason] }
  end

  # RFC 9846 "Alert Protocol" names decrypt_error for a PSK binder.
  def test_a_binder_that_does_not_verify
    ch = offered_client_hello
    assert_equal [:decrypt_error, :psk_binder_mismatch], failure(serve(ch.with_binders(["\x00".b * 32])))
  end

  # The first identity that passes is selected, and only its binder is
  # verified: the other's binder is all zeros.
  # A ClientHello offering the tickets of `sessions`, with the binder of the
  # one at `index` made under its PSK and the others all zeros.
  def offering(sessions, index:)
    identities = sessions.map { |s| TLS::Extension::PreSharedKey::Identity.new(identity: s.ticket, obfuscated_ticket_age: 0) }
    psk = TLS::Extension::PreSharedKey::CH.new(identities:, binders: ["\x00".b * 32] * sessions.size)
    ch = offered_client_hello(sessions.first)
    ch = ch.with(extensions: ch.extensions[0...-1] + [psk])
    transcript_hash = OpenSSL::Digest.digest("SHA256", ch.encode_truncated)
    binder = TLS::KeySchedule.new(hash: :sha256, psk: sessions.fetch(index).psk).binder(kind: :resumption, transcript_hash:)
    ch.with_binders(Array.new(sessions.size) { |i| i == index ? binder : "\x00".b * 32 })
  end

  # The first identity whose ticket opens and passes is the one whose
  # binder counts: a wrong one fails the handshake though a later identity
  # would have done.
  def test_the_binder_of_the_first_identity_that_passes
    first, second = sessions(handshake(Pair.client, { config: server_config }).client)
    assert_equal [:decrypt_error, :psk_binder_mismatch], failure(serve(offering([first, second], index: 1)))
  end

  # A ticket that opens but fails a check is passed over for the next.
  def test_a_ticket_passed_over_for_the_next
    stale = session
    later = NOW + 7300
    fresh = sessions(handshake(Pair.client(now: later - 100), { config: server_config }, now: later - 100).client).first
    tracer = Recorder.new
    server = Pair.server(offering([stale, fresh], index: 1).encode, config: server_config, tracer:, now: later)
    server_hello = TLS::Handshake.parse(server.outputs.find { |o| o.is_a?(TLS::Output::Message) }.bytes, registry: REGISTRY)
    assert_equal 1, server_hello.extension(TLS::Extension::PreSharedKey::TYPE).selected_identity
    assert_equal [[0, :ticket_expired]], tracer.values.grep(TLS::Trace::PskRejected).map { |r| [r.index, r.reason] }
  end

  # A session of SHA-384, the second of the hashes this server's transcript
  # runs: the binder is checked under it.
  def test_a_session_of_the_second_hash
    config = Pair.client_config(cipher_suites: %i[TLS_AES_256_GCM_SHA384])
    session = sessions(handshake(Pair.client(config:), { config: server_config }).client).first
    assert_equal 0x1302, session.cipher_suite
    tracer = Recorder.new
    pair = handshake(Pair.client(config:, session:, now: NOW + 60), { config: server_config, tracer: }, now: NOW + 60)
    assert completion(pair.server).resumed
    assert_equal [TLS::Trace::BinderVerified.new(index: 0)], tracer.values.grep(TLS::Trace::BinderVerified)
  end

  # A ClientHello with a PSK may leave out signature_algorithms (RFC 9846
  # "Mandatory-to-Implement Extensions"): a server that resumes needs none,
  # and only one that falls back to a certificate asks for it.
  def test_a_resumption_without_signature_algorithms
    session = self.session
    ch = offered_client_hello(session)
    ch = ch.with(extensions: ch.extensions.reject { |ext| ext.extension_type == TLS::Extension::SignatureAlgorithms::TYPE })
    transcript_hash = OpenSSL::Digest.digest("SHA256", ch.encode_truncated)
    binder = TLS::KeySchedule.new(hash: :sha256, psk: session.psk).binder(kind: :resumption, transcript_hash:)
    hello = ch.with_binders([binder]).encode
    refute serve(TLS::Handshake.parse(hello, registry: REGISTRY)).failed?
    other = Pair.server(hello, config: server_config(ticket_key: "\x0e".b * 32))
    assert_equal [:missing_extension, :signature_algorithms], failure(other)
  end

  def test_the_first_identity_that_passes
    session = self.session
    real = offered_client_hello(session).extensions.last.identities.first
    bogus = TLS::Extension::PreSharedKey::Identity.new(identity: "x".b * 40, obfuscated_ticket_age: 0)
    psk = TLS::Extension::PreSharedKey::CH.new(identities: [bogus, real], binders: ["\x00".b * 32] * 2)
    ch = offered_client_hello(session)
    ch = ch.with(extensions: ch.extensions[0...-1] + [psk])
    transcript_hash = OpenSSL::Digest.digest("SHA256", ch.encode_truncated)
    binder = TLS::KeySchedule.new(hash: :sha256, psk: session.psk).binder(kind: :resumption, transcript_hash:)
    tracer = Recorder.new
    server = serve(ch.with_binders(["\x00".b * 32, binder]), tracer:)
    server_hello = TLS::Handshake.parse(server.outputs.find { |o| o.is_a?(TLS::Output::Message) }.bytes, registry: REGISTRY)
    assert_equal 1, server_hello.extension(TLS::Extension::PreSharedKey::TYPE).selected_identity
    assert_equal [[0, :unknown_version]], tracer.values.grep(TLS::Trace::PskRejected).map { |r| [r.index, r.reason] }
    assert_equal [TLS::Trace::BinderVerified.new(index: 1)], tracer.values.grep(TLS::Trace::BinderVerified)
  end
end
