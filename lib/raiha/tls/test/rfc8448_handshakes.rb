# frozen_string_literal: true

module Raiha::TLS::Test::RFC8448
  # A Machine playing one side of an RFC 8448 trace: the client or the server
  # of section 3 (:simple_1rtt), 5 (:hello_retry_request) or 6
  # (:client_authentication), or the client of section 4 (:resumed_0rtt),
  # with the trace's randoms and key shares injected.
  #
  # RFC 8448 comes from NSS, and some of what it sends this implementation
  # never builds: TLS 1.2 extensions and groups it does not implement in the
  # ClientHello, a cookie in the HelloRetryRequest, padding in the second
  # ClientHello, NSS's own EncryptedExtensions, RSASSA-PSS signatures with
  # random salts, and certificates whose keys section 6 does not publish.
  # Those messages are replaced by the trace's bytes as they are sent, which
  # only this method can ask for. Everything the Machine derives from the
  # peer's messages, and every message it can build itself (ServerHello,
  # Certificate in sections 3 and 5, Finished), is its own.
  #
  # The peer's certificates are not verified: the trace's are long expired
  # and name no host.
  def self.machine(section, role, now:, keylog: nil)
    return resumed_client(now:, keylog:) if section == :resumed_0rtt && role == :client
    vectors = { simple_1rtt: Simple1RTT, hello_retry_request: HelloRetryRequest, client_authentication: ClientAuthentication }
    trace = vectors.fetch(section)
    tls = Raiha::TLS
    none = tls::Verifier::None.new
    if role == :client
      client_hello = section == :hello_retry_request ? HelloRetryRequest::CLIENT_HELLO_1 : trace.const_get(:CLIENT_HELLO)
      groups = section == :hello_retry_request ? %i[x25519 secp256r1] : %i[x25519]
      keys = { x25519: trace.const_get(:CLIENT_X25519_PRIVATE_KEY) }
      keys[:secp256r1] = HelloRetryRequest::CLIENT_SECP256R1_PRIVATE_KEY if section == :hello_retry_request
      config = tls::Config.deterministic(groups:)
      keyring = tls::Keyring.client(
        config:, identities: section == :client_authentication ? [server_identity] : [], verifier: none,
        key_exchange: Raiha::TLS::Test::FixedKEM.new(keys),
        random: Raiha::TLS::Test::FixedRandom.new(client_hello.byteslice(6, 32).to_s, "\x00".b * 32)
      )
      substitutions = { 1 => [client_hello] }
      substitutions[1] << HelloRetryRequest::CLIENT_HELLO_2 if section == :hello_retry_request
      if section == :client_authentication
        substitutions[11] = [ClientAuthentication::CLIENT_CERTIFICATE]
        substitutions[15] = [ClientAuthentication::CLIENT_CERTIFICATE_VERIFY]
      end
      tls::Handshake::Machine.__send__(:start_client, config:, keyring:, server_name: "server", now:, extensions: [],
        tracer: nil, keylog:, substitutions:)
    else
      server_hello = trace.const_get(:SERVER_HELLO)
      group, key = if section == :hello_retry_request
        [:secp256r1, HelloRetryRequest::SERVER_SECP256R1_PRIVATE_KEY]
      else
        [:x25519, trace.const_get(:SERVER_X25519_PRIVATE_KEY)]
      end
      config = tls::Config.server(groups: [group], client_auth: section == :client_authentication ? :required : :none)
      keyring = tls::Keyring.server(
        config:, identities: [server_identity], verifier: none,
        key_exchange: Raiha::TLS::Test::FixedKEM.new({ group => key }),
        random: Raiha::TLS::Test::FixedRandom.new(server_hello.byteslice(6, 32).to_s)
      )
      substitutions = { 8 => [trace.const_get(:ENCRYPTED_EXTENSIONS)] }
      substitutions[2] = [HelloRetryRequest::HELLO_RETRY_REQUEST] if section == :hello_retry_request
      if section == :client_authentication
        substitutions[13] = [ClientAuthentication::CERTIFICATE_REQUEST]
        substitutions[11] = [ClientAuthentication::SERVER_CERTIFICATE]
        substitutions[15] = [ClientAuthentication::SERVER_CERTIFICATE_VERIFY]
      else
        substitutions[15] = [trace.const_get(:CERTIFICATE_VERIFY)]
      end
      tls::Handshake::Machine.__send__(:start_server, config:, keyring:, client_hello: nil, now:, extensions: [],
        tracer: nil, keylog:, substitutions:)
    end
  end

  # The client of section 4, resuming the session of section 3's
  # NewSessionTicket with 0-RTT. Its ClientHello is NSS's up to the binders,
  # the binders its own. The session says its server was verified, as the
  # one section 3's client would keep: a client offers no session from a
  # server Verifier::None let in.
  def self.resumed_client(now:, keylog:)
    tls = Raiha::TLS
    config = tls::Config.deterministic(groups: %i[x25519])
    keyring = tls::Keyring.client(
      config:, verifier: tls::Verifier::None.new,
      key_exchange: Raiha::TLS::Test::FixedKEM.new({ x25519: Resumed0RTT::CLIENT_X25519_PRIVATE_KEY }),
      random: Raiha::TLS::Test::FixedRandom.new(Resumed0RTT::CLIENT_HELLO.byteslice(6, 32).to_s, "\x00".b * 32)
    )
    tls::Handshake::Machine.__send__(:start_client, config:, keyring:, server_name: "server", now:, extensions: [],
      tracer: nil, keylog:, substitutions: { 1 => [Resumed0RTT::CLIENT_HELLO] }, session: section3_session(now:), early_data: true)
  end

  # The session section 3's NewSessionTicket gives, received at `now`.
  def self.section3_session(now:)
    tls = Raiha::TLS
    ticket = case (message = tls::Handshake.parse(Simple1RTT::NEW_SESSION_TICKET, registry: tls::Extension::Registry::BUILTIN))
      when tls::Handshake::NewSessionTicket then message
      else raise "not a NewSessionTicket"
      end
    early_data = case (ext = ticket.extension(tls::Extension::EarlyData::TYPE))
      when tls::Extension::EarlyData::NST then ext
      else raise "no early_data"
      end
    now_ms = (now.to_r * 1000).floor
    tls::Session.new(ticket: ticket.ticket, ticket_nonce: ticket.ticket_nonce, resumption_secret: Simple1RTT::RESUMPTION_SECRET,
      cipher_suite: 0x1301, issued_at: now_ms, lifetime: ticket.ticket_lifetime, age_add: ticket.ticket_age_add,
      max_early_data_size: early_data.max_early_data_size, server_name: "server", alpn: nil,
      peer_certificates: server_identity.cert_der, authenticated_at: now_ms, peer_verified: true)
  end

  # The certificate of sections 3 to 5 with the key of section 2.
  def self.server_identity
    tls = Raiha::TLS
    certificate = tls::Handshake.parse(Simple1RTT::CERTIFICATE, registry: tls::Extension::Registry::BUILTIN)
    der = case certificate
      when tls::Handshake::Certificate then certificate.certificate_list.fetch(0).cert_data
      else raise "not a Certificate"
      end
    tls::Keyring::Identity.new(cert_der: [der], key_der: SERVER_RSA_PRIVATE_KEY)
  end
end
