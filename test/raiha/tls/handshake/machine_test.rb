require "test_helper"
require "support/tls_pair"
require "timeout"

# A client and a server Machine against each other: the full handshake,
# HelloRetryRequest, client authentication, and what comes out.
class RaihaNextTLSMachineTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Pair = NextTLSPair
  NOW = Pair::NOW
  TRANSPORT_PARAMETERS = TLS::Extension::Opaque

  def events(machine) = machine.each_event.to_a

  def complete(machine) = events(machine).grep(TLS::Event::HandshakeComplete).first

  def test_full_handshake
    pair = Pair.run(Pair.client)
    assert pair.client.complete?
    assert pair.server.complete?
    client_done = complete(pair.client)
    server_done = complete(pair.server)
    assert_equal ["localhost", :TLS_AES_128_GCM_SHA256, :x25519, false, true],
      [client_done.server_name, client_done.cipher_suite, client_done.group, client_done.resumed, client_done.peer_verified]
    assert_equal ["localhost", [], false], [server_done.server_name, server_done.peer_certificates, server_done.peer_verified]
    assert_equal 2, client_done.peer_certificates.size
    assert_equal [:application, :application], [pair.client.read_epoch, pair.client.write_epoch]
    assert_equal [:application, :application], [pair.server.read_epoch, pair.server.write_epoch]
  end

  # The output sequence of a full handshake: within one trigger the Secrets
  # that became usable come before the Messages.
  def test_outputs_of_a_full_handshake
    pair = Pair.run(Pair.client)
    assert_equal [
      [:message, :initial, 1],
      [:secret, :handshake, :read], [:secret, :handshake, :write],
      [:secret, :application, :read], [:secret, :application, :write], [:message, :handshake, 20]
    ], Pair.shape(pair.client_outputs)
    assert_equal [
      [:secret, :handshake, :read], [:secret, :handshake, :write], [:secret, :application, :write],
      [:message, :initial, 2], [:message, :handshake, 8], [:message, :handshake, 11], [:message, :handshake, 15],
      [:message, :handshake, 20],
      [:secret, :application, :read]
    ], Pair.shape(pair.server_outputs)
  end

  # Both sides derive the same secrets for each epoch and direction.
  def test_secrets_match
    pair = Pair.run(Pair.client)
    secrets = ->(outputs) { outputs.grep(TLS::Output::Secret).to_h { |s| [[s.epoch, s.direction], s.secret] } }
    client, server = secrets.(pair.client_outputs), secrets.(pair.server_outputs)
    %i[handshake application].each do |epoch|
      assert_equal client.fetch([epoch, :write]), server.fetch([epoch, :read]), epoch
      assert_equal client.fetch([epoch, :read]), server.fetch([epoch, :write]), epoch
    end
  end

  def quic_pair(client_alpn: ["h3"], server_alpn: ["h3"])
    client_config = Pair.client_config(profile: TLS::Profile::QUIC, alpn: client_alpn)
    server_config = Pair.server_config(profile: TLS::Profile::QUIC, alpn: server_alpn)
    client = Pair.client(config: client_config, extensions: [TRANSPORT_PARAMETERS.new(type: 0x39, data: "client tp".b)])
    Pair.run(client, { config: server_config, extensions: [TRANSPORT_PARAMETERS.new(type: 0x39, data: "server tp".b)] })
  end

  # QUIC: no compatibility mode, transport parameters both ways, ALPN.
  def test_quic
    pair = quic_pair
    assert pair.client.complete?
    assert pair.server.complete?
    client_events, server_events = events(pair.client), events(pair.server)
    assert_equal ["server tp"], client_events.grep(TLS::Event::PeerExtension).map(&:data)
    assert_equal ["client tp"], server_events.grep(TLS::Event::PeerExtension).map(&:data)
    assert_equal "h3", pair.client.alpn
    hello = TLS::Handshake.parse(pair.client_outputs.first.bytes, registry: TLS::Extension::Registry::BUILTIN)
    assert_empty hello.legacy_session_id
  end

  # RFC 9001 "Application-Layer Protocol Negotiation".
  def test_quic_requires_alpn
    pair = quic_pair(server_alpn: ["other"])
    assert_equal :no_application_protocol, pair.server.alert
  end

  def test_alpn_follows_the_server_preference
    client = Pair.client(config: Pair.client_config(alpn: %w[h2 h3]))
    pair = Pair.run(client, { config: Pair.server_config(alpn: %w[h3 h2]) })
    assert_equal ["h3", "h3"], [pair.client.alpn, pair.server.alpn]
    pair = Pair.run(Pair.client(config: Pair.client_config(alpn: %w[h2])), { config: Pair.server_config(alpn: %w[h3]) })
    assert_equal :no_application_protocol, pair.server.alert
  end

  # The server prefers secp256r1, for which the client sent no share.
  def test_hello_retry_request
    pair = Pair.run(Pair.client, { config: Pair.server_config(groups: %i[secp256r1]) })
    assert pair.client.complete?
    assert pair.server.complete?
    assert_equal :secp256r1, pair.client.group
    assert_equal [[:message, :initial, 1], [:message, :initial, 1]], Pair.shape(pair.client_outputs).first(2)
    assert_equal [:message, :initial, 2], Pair.shape(pair.server_outputs).first
    retry_request = TLS::Handshake.parse(pair.server_outputs.first.bytes, registry: TLS::Extension::Registry::BUILTIN)
    assert retry_request.hello_retry_request?
  end

  def client_auth_pair(mode, identities: [Pair.client_identity])
    client = Pair.client(identities:)
    Pair.run(client, { config: Pair.server_config(client_auth: mode) })
  end

  def test_client_authentication
    pair = client_auth_pair(:required)
    assert pair.server.complete?
    done = complete(pair.server)
    assert done.peer_verified
    assert_equal "client", done.peer_certificates.first.subject.to_a.assoc("CN")[1]
    assert_includes Pair.shape(pair.server_outputs), [:message, :handshake, 13]
    assert_equal [[:message, :handshake, 11], [:message, :handshake, 15], [:message, :handshake, 20]],
      Pair.shape(pair.client_outputs).last(3)
  end

  # Without an identity the client sends an empty Certificate and no
  # CertificateVerify: :optional goes on, :required fails.
  def test_client_authentication_without_an_identity
    pair = client_auth_pair(:optional, identities: [])
    assert pair.server.complete?
    done = complete(pair.server)
    assert_equal [[], false], [done.peer_certificates, done.peer_verified]
    assert_equal [[:message, :handshake, 11], [:message, :handshake, 20]], Pair.shape(pair.client_outputs).last(2)
    pair = client_auth_pair(:required, identities: [])
    assert_equal :certificate_required, pair.server.alert
  end

  def test_exporters_agree
    labels = ["EXPORTER-Channel-Binding"]
    client = Pair.client(config: Pair.client_config(exporter_labels: labels))
    pair = Pair.run(client, { config: Pair.server_config(exporter_labels: labels) })
    exported = [pair.client, pair.server].map { |m| m.export_keying_material(label: labels.first, length: 32) }
    assert_equal exported.first, exported.last
    assert_equal exported.first, pair.client.export_keying_material(label: labels.first, length: 32, context: "")
    refute_equal exported.first, pair.client.export_keying_material(label: labels.first, length: 32, context: "x")
    assert_raises(TLS::UsageError) { pair.client.export_keying_material(label: "EXPORTER-other", length: 32) }
    assert_raises(TLS::UsageError) { Pair.client.export_keying_material(label: labels.first, length: 32) }
  end

  # RFC 9846 "Key and Initialization Vector Update": the next read Secret at
  # once; our own KeyUpdate under the old key, then our next write Secret,
  # right before our next application data.
  def test_key_update_over_tcp
    pair = Pair.run(Pair.client)
    old_write = pair.client_outputs.grep(TLS::Output::Secret).find { |s| s.epoch == :application && s.direction == :write }
    requested = TLS::Handshake::KeyUpdate.new(request_update: 1).encode
    pair.client.receive(requested, epoch: :application, now: NOW)
    assert_equal [[:secret, :application, :read]], Pair.shape(pair.client.outputs)
    pair.client.before_application_data
    outputs = pair.client.outputs
    assert_equal [[:message, :application, 24], [:secret, :application, :write]], Pair.shape(outputs)
    expected = TLS::KeySchedule.expand_label(secret: old_write.secret, label: "traffic upd", length: 32, hash: :sha256)
    assert_equal expected, outputs.last.secret
    assert_equal 0, TLS::Handshake.parse(outputs[0].bytes, registry: TLS::Extension::Registry::BUILTIN).request_update

    pair.client.receive(TLS::Handshake::KeyUpdate.new(request_update: 0).encode, epoch: :application, now: NOW)
    pair.client.before_application_data
    assert_equal [[:secret, :application, :read]], Pair.shape(pair.client.outputs)
  end

  # RFC 8449: each side learns the limit the other sent. A server without
  # its own still learns the client's; the client then learns none.
  def test_peer_record_size_limit
    {
      [1000, 2000] => [2000, 1000],
      [1000, nil] => [nil, 1000],
      [nil, 2000] => [nil, nil]
    }.each do |(client_limit, server_limit), expected|
      pair = Pair.run(Pair.client(config: Pair.client_config(record_size_limit: client_limit)),
        { config: Pair.server_config(record_size_limit: server_limit) })
      assert pair.client.complete?
      assert_equal expected, [pair.client.peer_record_size_limit, pair.server.peer_record_size_limit], [client_limit, server_limit].inspect
    end
  end

  # Whether part of a message has come, before and after the Acceptor.
  def test_partial_message
    client = Pair.client
    hello = client.outputs.first.bytes
    config = Pair.server_config
    server = TLS::Handshake::Machine.server(config:, keyring: Pair.server_keyring(config:), now: NOW)
    refute server.partial_message?
    server.receive(hello.byteslice(0, 10).to_s, epoch: :initial, now: NOW)
    assert server.partial_message?
    server.receive(hello.byteslice(10..).to_s, epoch: :initial, now: NOW)
    refute server.partial_message?
    Pair.deliver(server.outputs, client)
    refute client.partial_message?
    client.receive("\x04\x00".b, epoch: :application, now: NOW)
    assert client.partial_message?
  end

  # RFC 9001 "Key Update": no KeyUpdate message in QUIC.
  def test_no_key_update_in_quic
    pair = quic_pair
    pair.server.receive(TLS::Handshake::KeyUpdate.new(request_update: 0).encode, epoch: :application, now: NOW)
    assert_equal :unexpected_message, pair.server.alert
  end

  def test_wrong_epoch
    client = Pair.client
    client.outputs
    client.receive("\x02\x00\x00\x00".b, epoch: :handshake, now: NOW)
    assert_equal [[:alert, :initial, :unexpected_message]], Pair.shape(client.outputs)
    assert_equal :wrong_epoch, events(client).grep(TLS::Event::Failed).first.reason
  end

  # A ServerHello and the next message in one piece of :initial bytes: the
  # EncryptedExtensions would span the key change.
  def test_handshake_data_spanning_a_key_change
    client = Pair.client
    server = Pair.server(client.outputs.first.bytes)
    messages = server.outputs.grep(TLS::Output::Message)
    client.receive(messages[0].bytes + messages[1].bytes, epoch: :initial, now: NOW)
    assert_equal :unexpected_message, client.alert
    assert_equal :handshake_data_spans_key_change, events(client).grep(TLS::Event::Failed).first.reason
  end

  def test_discard
    client = Pair.client
    client.outputs
    client.discard
    client.discard
    assert client.failed?
    assert_empty client.outputs
    assert_empty events(client)
    client.receive("\x02\x00\x00\x00".b, epoch: :initial, now: NOW)
    assert_empty client.outputs
  end

  # The most the peer can send per epoch, from the per-type limits.
  def test_max_flight_size
    h, c = 16 * 1024, 256 * 1024
    client = Pair.client
    assert_equal [h, 2 * c + 3 * h, h, 0], %i[initial handshake application early_data].map { |e| client.max_flight_size(e) }
    server = Pair.server(client.outputs.first.bytes)
    assert_equal [h, h, 0, 0], %i[initial handshake application early_data].map { |e| server.max_flight_size(e) }
    client = Pair.client
    authenticating = Pair.server(client.outputs.first.bytes, config: Pair.server_config(client_auth: :required))
    assert_equal c + 2 * h, authenticating.max_flight_size(:handshake)
  end

  def test_constructor_checks
    config = Pair.client_config
    other = TLS::Keyring.client(config: Pair.client_config)
    assert_raises(ArgumentError) { TLS::Handshake::Machine.client(config:, keyring: other, server_name: "localhost", now: NOW) }
    keyring = TLS::Keyring.client(config:)
    assert_raises(ArgumentError) { TLS::Handshake::Machine.client(config:, keyring:, server_name: "bad name", now: NOW) }
    assert_raises(ArgumentError) do
      TLS::Handshake::Machine.client(config:, keyring:, server_name: "localhost", now: NOW,
        extensions: [TLS::Extension::Opaque.new(type: 0, data: "".b)])
    end
  end

  # A server Config that takes 0-RTT needs a record of what was taken, or
  # its tickets would allow 0-RTT it could never take.
  def test_a_server_that_takes_0rtt_needs_an_anti_replay_record
    config = Pair.server_config(ticket_key: "\x01".b * 32, max_early_data_size: 1024)
    keyring = Pair.server_keyring(config:)
    assert_raises(TLS::UsageError) { TLS::Handshake::Machine.server(config:, keyring:, now: NOW) }
    anti_replay = TLS::AntiReplay::Memory.new(now: NOW)
    assert TLS::Handshake::Machine.server(config:, keyring:, now: NOW, anti_replay:)
    plain = Pair.server_config
    assert TLS::Handshake::Machine.server(config: plain, keyring: Pair.server_keyring(config: plain), now: NOW)
  end

  # An IP address is checked against the certificate but never sent as SNI.
  def test_ip_address_server_name
    client = Pair.client(server_name: "192.0.2.1")
    hello = TLS::Handshake.parse(client.outputs.first.bytes, registry: TLS::Extension::Registry::BUILTIN)
    assert_nil hello.extension(0)
  end
end

# The self round trip of the API design, as written there: no records, no
# sockets, the server taking its ClientHello through `receive`.
class RaihaNextTLSSixLineRoundTripTest < Minitest::Test
  TLS = Raiha::Next::TLS

  def test_six_lines
    c, s, now = NextTLSPair.client_config, NextTLSPair.server_config, NextTLSPair::NOW
    ck, sk = TLS::Keyring.client(config: c), NextTLSPair.server_keyring(config: s)
    client = TLS::Handshake::Machine.client(config: c, keyring: ck, server_name: "localhost", now:)
    server = TLS::Handshake::Machine.server(config: s, keyring: sk, now:)

    Timeout.timeout(5) do
      until client.complete? && server.complete?
        client.outputs.each { |o| server.receive(o.bytes, epoch: o.epoch, now:) if o in TLS::Output::Message }
        server.outputs.each { |o| client.receive(o.bytes, epoch: o.epoch, now:) if o in TLS::Output::Message }
      end
    end
    refute client.failed?
  end
end
