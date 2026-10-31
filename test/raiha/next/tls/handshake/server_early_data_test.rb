require "raiha/next/test_helper"
require "raiha/next/support/tls_pair"

# A server's 0-RTT: taken only on the first identity's ticket that allows
# it, under the Config that allows it, the same cipher suite, ALPN protocol
# and early_data_context, a ticket age within the window, and the
# anti-replay record's :accepted, in that order; any other way rejected with
# the reason, the handshake going on.
class RaihaNextTLSServerEarlyDataTest < Minitest::Test
  Pair = NextTLSPair
  TLS = Pair::TLS
  NOW = Pair::NOW
  SEED = "\x11".b * 32
  REGISTRY = TLS::Extension::Registry::BUILTIN
  TRANSPORT_PARAMETERS = TLS::Extension::Opaque

  class Recorder
    attr_reader :values

    def initialize = @values = []

    def tls_trace(value) = @values << value
  end

  def events(machine) = [].tap { |all| machine.each_event { all << _1 } }

  def server_config(**options) = Pair.server_config(ticket_key: SEED, max_early_data_size: 1024, **options)

  def session_from(pair, now: NOW)
    Pair.deliver(pair.server_outputs.select { |output| output.is_a?(TLS::Output::Message) && output.epoch == :application }, pair.client, now:)
    events(pair.client).grep(TLS::Event::NewSessionTicket).first.session
  end

  # A session whose ticket allows 0-RTT, with `server_options` at issue.
  def session(**server_options) = session_from(Pair.run(Pair.client, { config: server_config, **server_options }))

  def completion(machine) = events(machine).grep(TLS::Event::HandshakeComplete).first

  def shape(outputs) = Pair.shape(outputs)

  def test_a_server_takes_0rtt
    session = self.session
    later = NOW + 60
    pair = Pair.run(Pair.client(session:, early_data: true, now: later), { config: server_config }, now: later)
    assert completion(pair.client).early_data_accepted
    assert completion(pair.server).early_data_accepted
    client_key = pair.client_outputs.grep(TLS::Output::Secret).find { |s| s.epoch == :early_data }
    server_key = pair.server_outputs.grep(TLS::Output::Secret).find { |s| s.epoch == :early_data }
    assert_equal [:read, client_key.secret], [server_key.direction, server_key.secret]
    assert_equal [[:secret, :early_data, :read], [:secret, :handshake, :read], [:secret, :handshake, :write], [:secret, :application, :write],
      [:message, :initial, 2], [:message, :handshake, 8], [:message, :handshake, 20]], shape(pair.server_outputs).first(7)
    ee = TLS::Handshake.parse(pair.server_outputs.grep(TLS::Output::Message).find { |o| o.bytes.getbyte(0) == 8 }.bytes, registry: REGISTRY)
    assert ee.extension(TLS::Extension::EarlyData::TYPE)
    # EndOfEarlyData came under the 0-RTT key, then the client Finished.
    assert_equal [[:message, :early_data, 5], [:message, :handshake, 20]],
      shape(pair.client_outputs).select { |o| o.first == :message && o[1] != :initial }.first(2)
    assert_equal [:application, :application], [pair.server.read_epoch, pair.server.write_epoch]
  end

  # QUIC sends no EndOfEarlyData, and takes 0-RTT only with the
  # early_data_context the layer above gives.
  def test_a_quic_server_takes_0rtt
    client_config = Pair.client_config(profile: TLS::Profile::QUIC, alpn: ["h3"])
    config = server_config(profile: TLS::Profile::QUIC, alpn: ["h3"])
    client_tp = [TRANSPORT_PARAMETERS.new(type: 0x39, data: "client tp".b)]
    server = { config:, extensions: [TRANSPORT_PARAMETERS.new(type: 0x39, data: "server tp".b)], early_data_context: "settings".b }
    session = session_from(Pair.run(Pair.client(config: client_config, extensions: client_tp), server))
    pair = Pair.run(Pair.client(config: client_config, extensions: client_tp, session:, early_data: true, now: NOW + 1), server, now: NOW + 1)
    assert completion(pair.server).early_data_accepted
    refute_includes shape(pair.client_outputs), [:message, :early_data, 5]
    # Without a context there is nothing to take it by.
    tracer = Recorder.new
    pair = Pair.run(Pair.client(config: client_config, extensions: client_tp, session:, early_data: true, now: NOW + 1),
      server.merge(early_data_context: "".b, tracer:), now: NOW + 1)
    assert_equal [:early_data_context_mismatch], tracer.values.grep(TLS::Trace::EarlyDataRejected).map(&:reason)
  end

  # The reason a server rejects 0-RTT for, as its event and its trace, the
  # handshake completing without it.
  def rejected(session:, client_config: Pair.client_config, client_now: NOW + 60, now: NOW + 60, **server_options)
    tracer = Recorder.new
    client = Pair.client(config: client_config, session:, early_data: true, now: client_now)
    server = Pair.server(client.outputs.grep(TLS::Output::Message).first.bytes, tracer:, now:, **{ config: server_config }.merge(server_options))
    20.times do
      Pair.deliver(server.outputs, client, now:)
      Pair.deliver(client.outputs, server, now:)
      break if (client.complete? && server.complete?) || client.failed? || server.failed?
    end
    assert server.complete?, server_options.inspect
    all = events(server)
    refute all.grep(TLS::Event::HandshakeComplete).first.early_data_accepted
    reasons = all.grep(TLS::Event::EarlyDataRejected).map(&:reason)
    assert_equal reasons, tracer.values.grep(TLS::Trace::EarlyDataRejected).map(&:reason)
    reasons
  end

  def test_why_a_server_rejects_0rtt
    session = self.session
    assert_equal [:hello_retry_request], rejected(session:, config: server_config(groups: %i[secp256r1]))
    assert_equal [:psk_not_selected], rejected(session:, config: server_config(ticket_key: "\x12".b * 32))
    assert_equal [:ticket_disallows], rejected(session: self.session(config: Pair.server_config(ticket_key: SEED)).with(max_early_data_size: 1024))
    assert_equal [:config_disallows], rejected(session:, config: Pair.server_config(ticket_key: SEED))
    assert_equal [:cipher_suite_mismatch],
      rejected(session:, config: server_config(cipher_suites: %i[TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256]))
    assert_equal [:early_data_context_mismatch], rejected(session: self.session(early_data_context: "a".b), early_data_context: "b".b)
    # The client counts 30 seconds more than the server.
    assert_equal [:ticket_age_skew], rejected(session:, client_now: NOW + 60, now: NOW + 30)
    assert_equal [:anti_replay_unavailable], rejected(session:, anti_replay: TLS::AntiReplay::Memory.new(now: NOW + 60))
  end

  # How much of the client's 0-RTT a server's record layer skips: the
  # Config's max_early_data_size, 16 KiB at least, for 0-RTT offered and
  # not taken, else nothing; never for QUIC or a client.
  def test_how_much_rejected_0rtt_is_skipped
    session = self.session
    hello = Pair.client(session:, early_data: true, now: NOW + 60).outputs.grep(TLS::Output::Message).first.bytes
    taken = Pair.server(hello, config: server_config, now: NOW + 60)
    assert_nil taken.skip_early_data_limit
    rejected = Pair.server(hello, config: server_config(ticket_key: "\x12".b * 32), now: NOW + 60)
    assert_equal 16_384, rejected.skip_early_data_limit
    large = Pair.server(hello, config: server_config(max_early_data_size: 65_536, ticket_key: "\x12".b * 32), now: NOW + 60)
    assert_equal 65_536, large.skip_early_data_limit
    # A server that takes no 0-RTT skips it all the same.
    none = Pair.server(hello, config: Pair.server_config(ticket_key: SEED), now: NOW + 60)
    assert_equal 16_384, none.skip_early_data_limit
    retried = Pair.server(hello, config: server_config(groups: %i[secp256r1]), now: NOW + 60)
    assert_equal [16_384, :initial], [retried.skip_early_data_limit, retried.read_epoch]
    plain = Pair.server(Pair.client.outputs.first.bytes, config: server_config)
    assert_nil plain.skip_early_data_limit
    assert_nil Pair.client(session:, early_data: true).skip_early_data_limit
  end

  # The same ClientHello's 0-RTT is taken once; the second server that
  # shares the record rejects it.
  def test_a_replayed_client_hello
    session = self.session
    hello = Pair.client(session:, early_data: true, now: NOW + 60).outputs.grep(TLS::Output::Message).first.bytes
    anti_replay = TLS::AntiReplay::Memory.new(now: NOW, warmup: false)
    first = Pair.server(hello, config: server_config, anti_replay:, now: NOW + 60)
    second = Pair.server(hello, config: server_config, anti_replay:, now: NOW + 61)
    assert_empty events(first).grep(TLS::Event::EarlyDataRejected)
    assert_equal [:replayed], events(second).grep(TLS::Event::EarlyDataRejected).map(&:reason)
  end

  # A replay passes the freshness check no later than the record was asked
  # to keep the ClientHello: the server's clock is not rounded to
  # milliseconds.
  def test_the_record_outlives_the_freshness_window
    hello = Pair.client(session:, early_data: true, now: NOW + 60).outputs.grep(TLS::Output::Message).first.bytes
    asked = []
    record = Object.new
    record.define_singleton_method(:check) { |_binder, expires_at:, now:| asked << expires_at && :accepted }
    Pair.server(hello, config: server_config, anti_replay: record, now: NOW + 60 + Rational(4, 10_000))
    expires_at = asked.fetch(0)
    Pair.server(hello, config: server_config, anti_replay: record, now: expires_at)
    assert_equal 2, asked.size
    tracer = Recorder.new
    Pair.server(hello, config: server_config, anti_replay: record, now: expires_at + Rational(5, 10_000), tracer:)
    assert_equal 2, asked.size
    assert_equal [:ticket_age_skew], tracer.values.grep(TLS::Trace::EarlyDataRejected).map(&:reason)
  end

  # Only the first identity's 0-RTT is taken.
  def test_0rtt_on_another_identity
    session = self.session
    ch = TLS::Handshake.parse(Pair.client(session:, early_data: true).outputs.grep(TLS::Output::Message).first.bytes, registry: REGISTRY)
    bogus = TLS::Extension::PreSharedKey::Identity.new(identity: "x".b * 40, obfuscated_ticket_age: 0)
    real = ch.extensions.last.identities.first
    ch = ch.with(extensions: ch.extensions[0...-1] + [TLS::Extension::PreSharedKey::CH.new(identities: [bogus, real], binders: ["\x00".b * 32] * 2)])
    binder = TLS::KeySchedule.new(hash: :sha256, psk: session.psk)
      .binder(kind: :resumption, transcript_hash: OpenSSL::Digest.digest("SHA256", ch.encode_truncated))
    server = Pair.server(ch.with_binders(["\x00".b * 32, binder]).encode, config: server_config)
    assert_equal [:not_first_identity], events(server).grep(TLS::Event::EarlyDataRejected).map(&:reason)
  end

  # An anti-replay record outside its contract: an answer it may not give
  # is a UsageError, an exception goes through, and either way the server
  # has failed with its secrets forgotten and nothing sent.
  def test_an_anti_replay_record_outside_its_contract
    hello = Pair.client(session:, early_data: true, now: NOW + 60).outputs.grep(TLS::Output::Message).first.bytes
    config = server_config
    keyring = Pair.server_keyring(config:)
    lying = Object.new
    def lying.check(_binder, expires_at:, now:) = true
    broken = Object.new
    def broken.check(_binder, expires_at:, now:) = raise(IOError, "store unreachable")
    { TLS::UsageError => lying, IOError => broken }.each do |error, anti_replay|
      server = TLS::Handshake::Machine.server(config:, keyring:, now: NOW + 60, anti_replay:)
      assert_raises(error) { server.receive(hello, epoch: :initial, now: NOW + 60) }
      assert server.failed?
      assert_empty server.outputs
    end
  end
end
