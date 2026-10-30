require "raiha/next/test_helper"
require "raiha/next/support/tls_pair"

# A client's 0-RTT: sent only when asked and the server could take it, under
# a key from the PSK over the whole ClientHello, and rejected, with the
# reason, by a HelloRetryRequest, a ServerHello that does not select the PSK,
# or EncryptedExtensions without early_data.
class RaihaNextTLSClientEarlyDataTest < Minitest::Test
  Pair = NextTLSPair
  TLS = Pair::TLS
  NOW = Pair::NOW
  SEED = "\x0f".b * 32
  REGISTRY = TLS::Extension::Registry::BUILTIN

  class Recorder
    attr_reader :values

    def initialize = @values = []

    def tls_trace(value) = @values << value
  end

  def events(machine) = [].tap { |all| machine.each_event { all << _1 } }

  def server_config(**options) = Pair.server_config(ticket_key: SEED, max_early_data_size: 1024, **options)

  # A session whose ticket allows 0-RTT.
  def session
    @session ||= begin
      pair = Pair.run(Pair.client, { config: server_config })
      Pair.deliver(pair.server_outputs.select { |output| output.is_a?(TLS::Output::Message) && output.epoch == :application }, pair.client)
      events(pair.client).grep(TLS::Event::NewSessionTicket).first.session
    end
  end

  def test_a_client_sends_0rtt
    client = Pair.client(session:, early_data: true)
    secret, hello = client.outputs
    assert_equal [:early_data, :write, :TLS_AES_128_GCM_SHA256], [secret.epoch, secret.direction, secret.cipher_suite.name]
    assert_equal [TLS::Output::Message, :initial], [hello.class, hello.epoch]
    ch = TLS::Handshake.parse(hello.bytes, registry: REGISTRY)
    assert_equal [TLS::Extension::EarlyData::TYPE, TLS::Extension::PreSharedKey::TYPE], ch.extensions.last(2).map(&:extension_type)
    schedule = TLS::KeySchedule.new(hash: :sha256, psk: session.psk)
    assert_equal schedule.client_early_traffic_secret(OpenSSL::Digest.digest("SHA256", hello.bytes)), secret.secret
    assert_equal :early_data, client.write_epoch
  end

  def test_a_client_not_asked_sends_none
    tracer = Recorder.new
    client = Pair.client(session:, tracer:)
    outputs = client.outputs
    assert_equal [TLS::Output::Message], outputs.map(&:class)
    assert_nil TLS::Handshake.parse(outputs.first.bytes, registry: REGISTRY).extension(TLS::Extension::EarlyData::TYPE)
    assert_empty tracer.values.grep(TLS::Trace::EarlyDataNotAttempted)
  end

  # A session that cannot take 0-RTT is still offered, without it.
  def test_why_a_client_sends_no_0rtt
    {
      ticket_disallows: [session.with(max_early_data_size: 0), Pair.client_config],
      cipher_suite_not_offered: [session, Pair.client_config(cipher_suites: %i[TLS_CHACHA20_POLY1305_SHA256])],
      alpn_not_offered: [session.with(alpn: "h2".b), Pair.client_config]
    }.each do |reason, (session, config)|
      tracer = Recorder.new
      outputs = Pair.client(config:, session:, early_data: true, tracer:).outputs
      ch = TLS::Handshake.parse(outputs.grep(TLS::Output::Message).first.bytes, registry: REGISTRY)
      assert ch.extension(TLS::Extension::PreSharedKey::TYPE), reason
      assert_nil ch.extension(TLS::Extension::EarlyData::TYPE), reason
      assert_empty outputs.grep(TLS::Output::Secret), reason
      assert_equal [TLS::Trace::EarlyDataNotAttempted.new(reason:)], tracer.values.grep(TLS::Trace::EarlyDataNotAttempted), reason
    end
  end

  # The reason the client sees, the handshake going on without 0-RTT.
  def rejected(server_options, tracer: Recorder.new)
    pair = Pair.run(Pair.client(session:, early_data: true, tracer:), server_options)
    assert pair.client.complete?
    all = events(pair.client)
    complete = all.grep(TLS::Event::HandshakeComplete).first
    refute complete.early_data_accepted
    reasons = all.grep(TLS::Event::EarlyDataRejected).map(&:reason)
    assert_equal reasons, tracer.values.grep(TLS::Trace::EarlyDataRejected).map(&:reason)
    [reasons, complete, pair]
  end

  # This server resumes but takes no 0-RTT yet: EncryptedExtensions has no
  # early_data.
  def test_0rtt_rejected_by_the_server
    reasons, complete, pair = rejected({ config: server_config })
    assert_equal [:rejected_by_server], reasons
    assert complete.resumed
    refute_includes pair.client_outputs.grep(TLS::Output::Message).map(&:epoch), :early_data
  end

  def test_0rtt_rejected_by_a_server_that_does_not_resume
    reasons, = rejected({ config: server_config(ticket_key: "\x10".b * 32) })
    assert_equal [:psk_not_selected], reasons
  end

  # After a HelloRetryRequest the second ClientHello has no early_data, and
  # alerts go in the clear again.
  def test_0rtt_rejected_by_a_hello_retry_request
    client = Pair.client(session:, early_data: true)
    hello = client.outputs.grep(TLS::Output::Message).first
    server = Pair.server(hello.bytes, config: server_config(groups: %i[secp256r1]))
    Pair.deliver(server.outputs, client)
    assert_equal [:hello_retry_request], events(client).grep(TLS::Event::EarlyDataRejected).map(&:reason)
    assert_equal :initial, client.write_epoch
    second = TLS::Handshake.parse(client.outputs.grep(TLS::Output::Message).first.bytes, registry: REGISTRY)
    assert_nil second.extension(TLS::Extension::EarlyData::TYPE)
  end

  def test_early_data_is_true_or_false
    assert_raises(ArgumentError) { Pair.client(session:, early_data: nil) }
  end
end
