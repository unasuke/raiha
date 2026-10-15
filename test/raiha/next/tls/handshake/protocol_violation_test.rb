require "raiha/next/test_helper"
require "raiha/next/support/tls_pair"

# Profile::QUIC.protocol_violation_reasons, each caused for real: a QUIC
# binding maps these reasons to PROTOCOL_VIOLATION, so every value must be
# one the Machine actually reports, under its exact name.
class RaihaNextTLSProtocolViolationTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Pair = NextTLSPair
  NOW = Pair::NOW
  TRANSPORT_PARAMETERS = TLS::Extension::Opaque.new(type: 0x39, data: "tp".b)
  REGISTRY = TLS::Extension::Registry::BUILTIN

  def reason(machine) = machine.each_event.grep(TLS::Event::Failed).first&.reason

  def config(profile, role)
    options = profile == TLS::Profile::QUIC ? { profile:, alpn: ["h3"] } : { profile: }
    role == :client ? Pair.client_config(**options) : Pair.server_config(**options)
  end

  def client(profile) = Pair.client(config: config(profile, :client), extensions: profile_extensions(profile))

  def profile_extensions(profile) = profile == TLS::Profile::QUIC ? [TRANSPORT_PARAMETERS] : []

  def connected(profile)
    Pair.run(client(profile), { config: config(profile, :server), extensions: profile_extensions(profile) }).client
  end

  CAUSES = {
    handshake_data_spans_key_change: lambda do |test, profile|
      client = test.client(profile)
      server = Pair.server(client.outputs.first.bytes, config: test.config(profile, :server), extensions: test.profile_extensions(profile))
      first, second = server.outputs.grep(TLS::Output::Message)
      client.receive(first.bytes + second.bytes, epoch: :initial, now: NOW)
      client
    end,
    # The same as the last, before the server's Machine has its ClientHello:
    # bytes after it in the same Initial data.
    data_after_client_hello: lambda do |test, profile|
      Pair.server(test.client(profile).outputs.first.bytes + "\x02\x00".b, config: test.config(profile, :server),
        extensions: test.profile_extensions(profile))
    end,
    wrong_epoch: lambda do |test, profile|
      client = test.client(profile)
      client.receive("\x02\x00\x00\x00".b, epoch: :handshake, now: NOW)
      client
    end,
    post_handshake_certificate_request: lambda do |test, profile|
      client = test.connected(profile)
      request = TLS::Handshake::CertificateRequest.new(certificate_request_context: "".b,
        extensions: [TLS::Extension::SignatureAlgorithms.new(supported_signature_algorithms: [0x0403])])
      client.receive(request.encode, epoch: :application, now: NOW)
      client
    end,
    max_early_data_size_not_sentinel: lambda do |test, profile|
      client = test.connected(profile)
      ticket = TLS::Handshake::NewSessionTicket.new(ticket_lifetime: 7200, ticket_age_add: 0, ticket_nonce: "\x00".b,
        ticket: "t".b, extensions: [TLS::Extension::EarlyData::NST.new(max_early_data_size: 16384)])
      client.receive(ticket.encode, epoch: :application, now: NOW)
      client
    end,
    nonempty_legacy_session_id: lambda do |test, profile|
      hello = TLS::Handshake.parse(test.client(profile).outputs.first.bytes, registry: REGISTRY)
      Pair.server(hello.with(legacy_session_id: "\x01".b * 32).encode, config: test.config(profile, :server),
        extensions: test.profile_extensions(profile))
    end
  }.freeze

  def test_every_reason_is_reported_under_quic
    assert_equal TLS::Profile::QUIC.protocol_violation_reasons.sort, CAUSES.keys.sort
    CAUSES.each do |expected, cause|
      machine = cause.call(self, TLS::Profile::QUIC)
      assert machine.failed?, expected
      assert_equal expected, reason(machine), expected
    end
  end

  # Over TCP the same failures that can happen there close with their
  # alert, and the TCP Profile maps none of them.
  def test_tcp_closes_with_the_alert
    assert_empty TLS::Profile::TCP.protocol_violation_reasons
    %i[handshake_data_spans_key_change wrong_epoch].each do |name|
      machine = CAUSES.fetch(name).call(self, TLS::Profile::TCP)
      assert_equal [:unexpected_message, name], [machine.alert, reason(machine)]
    end
    # TCP has middlebox compatibility mode, and tickets are not checked for
    # the QUIC sentinel.
    refute CAUSES.fetch(:nonempty_legacy_session_id).call(self, TLS::Profile::TCP).failed?
    refute CAUSES.fetch(:max_early_data_size_not_sentinel).call(self, TLS::Profile::TCP).failed?
  end
end
