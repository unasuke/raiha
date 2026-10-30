require "raiha/next/test_helper"
require "raiha/next/support/tls_pair"

# A client given a session: checked against its settings first, offered as a
# PSK whose binder is a MAC over the ClientHello up to the binders, or not
# offered, with the reason of the first check it fails.
class RaihaNextTLSSessionOfferTest < Minitest::Test
  Pair = NextTLSPair
  TLS = Pair::TLS
  PKI = Pair::PKI
  NOW = Pair::NOW
  SEED = "\x0c".b * 32

  def events(machine) = [].tap { |all| machine.each_event { all << _1 } }

  # A session from a full handshake with a server that issues tickets.
  def session
    @session ||= begin
      pair = Pair.run(Pair.client, { config: Pair.server_config(ticket_key: SEED) })
      Pair.deliver(pair.server_outputs.select { |output| output.is_a?(TLS::Output::Message) && output.epoch == :application }, pair.client)
      events(pair.client).grep(TLS::Event::NewSessionTicket).first.session
    end
  end

  def client_hello(machine)
    output = machine.outputs.find { |o| o.is_a?(TLS::Output::Message) } or raise "no ClientHello"
    [output.bytes, TLS::Handshake.parse(output.bytes, registry: TLS::Extension::Registry::BUILTIN)]
  end

  def test_a_session_is_offered
    now = NOW + 5
    bytes, ch = client_hello(Pair.client(session:, now:))
    psk = ch.extensions.last
    assert_instance_of TLS::Extension::PreSharedKey::CH, psk
    assert_equal [session.ticket], psk.identities.map(&:identity)
    assert_equal [session.obfuscated_ticket_age(now)], psk.identities.map(&:obfuscated_ticket_age)
    truncated = bytes.byteslice(0, bytes.bytesize - ch.binders_wire_length)
    expected = TLS::KeySchedule.new(hash: :sha256, psk: session.psk).binder(kind: :resumption, transcript_hash: OpenSSL::Digest.digest("SHA256", truncated))
    assert_equal [expected], psk.binders
    assert_equal [1], ch.extension(TLS::Extension::PskKeyExchangeModes::TYPE).ke_modes
  end

  # A server that takes no PSK answers it with a full handshake.
  def test_a_server_that_takes_no_psk
    pair = Pair.run(Pair.client(session:), { config: Pair.server_config })
    assert pair.client.complete? && pair.server.complete?
  end

  def refused(reason, now: NOW, **options)
    machine = Pair.client(now:, **options)
    _, ch = client_hello(machine)
    assert_nil ch.extension(TLS::Extension::PreSharedKey::TYPE), reason
    assert_equal [TLS::Event::SessionNotOffered.new(reason:)], events(machine).grep(TLS::Event::SessionNotOffered)
  end

  def test_sessions_not_offered
    refused(:ticket_expired, now: NOW + 7201, session:)
    leaf = OpenSSL::X509::Certificate.new(session.peer_certificates.first)
    later = leaf.not_after + 3600
    later_ms = (later.to_r * 1000).floor
    refused(:certificate_expired, now: later, session: session.with(issued_at: later_ms, authenticated_at: later_ms))
    refused(:unverified_origin, session: session.with(peer_verified: false))
    refused(:untrusted_chain, session:, config: TLS::Config.client(trust_anchors: [PKI.ca(name: "Another CA").der]))
    refused(:untrusted_chain, session: session.with(peer_certificates: ["not a certificate".b]))
    refused(:server_name_mismatch, session:, server_name: "other.example")
    refused(:cipher_suite_unavailable, session:, config: Pair.client_config(cipher_suites: %i[TLS_AES_256_GCM_SHA384]))
    # The checks after which no connection can use the session come first.
    refused(:ticket_expired, now: NOW + 7201, session:, server_name: "other.example")
  end

  def test_which_sessions_to_drop
    assert TLS::Event::SessionNotOffered.new(reason: :untrusted_chain).discard?
    refute TLS::Event::SessionNotOffered.new(reason: :server_name_mismatch).discard?
  end

  def test_a_client_that_does_not_resume_takes_no_session
    assert_raises(TLS::UsageError) { Pair.client(config: Pair.client_config(resumption: false), session:) }
    assert_raises(ArgumentError) { Pair.client(session: session.to_h) }
  end
end
