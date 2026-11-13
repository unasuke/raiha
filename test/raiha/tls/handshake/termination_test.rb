require "test_helper"
require "support/tls_pair"

# How a handshake ends when it does not complete: RFC 9846 "Alert
# Protocol" requires the secrets of a failed connection to be forgotten,
# whether the failure is found here, decided outside (`discard`), or raised
# by an object the caller gave.
class RaihaNextTLSTerminationTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Pair = NextTLSPair
  NOW = Pair::NOW

  def conductor(machine) = machine.instance_variable_get(:@conductor)

  def forgotten?(machine)
    schedule = conductor(machine).key_schedule
    (schedule.nil? || schedule.stage == :discarded) && conductor(machine).side.exporter_values.empty?
  end

  # A client halfway through: the key schedule holds handshake secrets.
  def midway(verifier: nil, tracer: nil, labels: [])
    keyring_options = verifier ? { verifier: } : {}
    client = Pair.client(config: Pair.client_config(exporter_labels: labels), tracer:, **keyring_options)
    server = Pair.server(client.outputs.first.bytes, config: Pair.server_config(exporter_labels: labels))
    flight = server.outputs.grep(TLS::Output::Message)
    client.receive(flight.first.bytes, epoch: :initial, now: NOW)
    [client, flight.drop(1)]
  end

  def test_a_failure_forgets_the_secrets
    client, _ = midway
    assert_equal :handshake, conductor(client).key_schedule.stage
    client.receive("\x14\x00\x00\x00".b, epoch: :handshake, now: NOW)
    assert client.failed?
    assert forgotten?(client)
  end

  def test_discard_forgets_the_secrets_after_completion
    pair = Pair.run(Pair.client(config: Pair.client_config(exporter_labels: ["EXPORTER-x"])),
      { config: Pair.server_config(exporter_labels: ["EXPORTER-x"]) })
    refute_empty conductor(pair.client).side.exporter_values
    pair.client.discard
    assert forgotten?(pair.client)
    assert_raises(TLS::UsageError) { pair.client.export_keying_material(label: "EXPORTER-x", length: 8) }
  end

  class RaisingVerifier
    def verify(chain:, server_name:, now:, purpose:) = raise(IOError, "pin store unreachable")
    def resumption_policy = nil
  end

  class WrongVerifier
    def verify(chain:, server_name:, now:, purpose:) = true
    def resumption_policy = nil
  end

  # The exception is the caller's object breaking its contract: it goes on
  # up, but the handshake is failed and its secrets gone first, with no
  # alert or event queued.
  def test_an_exception_from_the_verifier
    client, flight = midway(verifier: RaisingVerifier.new)
    client.outputs
    error = assert_raises(IOError) { flight.each { |m| client.receive(m.bytes, epoch: m.epoch, now: NOW) } }
    assert_equal "pin store unreachable", error.message
    assert client.failed?
    assert forgotten?(client)
    assert_empty client.outputs
    assert_empty client.each_event.to_a
    client.receive("\x14\x00\x00\x00".b, epoch: :handshake, now: NOW)
    assert_empty client.outputs
  end

  def test_a_verifier_that_returns_something_else
    client, flight = midway(verifier: WrongVerifier.new)
    client.outputs
    assert_raises(TLS::UsageError) { flight.each { |m| client.receive(m.bytes, epoch: m.epoch, now: NOW) } }
    assert client.failed?
    assert forgotten?(client)
    assert_empty client.outputs
  end

  class RaisingTracer
    def tls_trace(value)
      raise ArgumentError, "tracer broke" if value.is_a?(TLS::Trace::PeerSignatureVerified)
    end
  end

  def test_an_exception_from_the_tracer
    client, flight = midway(tracer: RaisingTracer.new)
    assert_raises(ArgumentError) { flight.each { |m| client.receive(m.bytes, epoch: m.epoch, now: NOW) } }
    assert client.failed?
    assert forgotten?(client)
  end

  # With no tracer no Trace value is built at all, across a handshake that
  # passes every check that reports one.
  def test_no_tracer_no_traces
    classes = TLS::Trace.constants.map { |name| TLS::Trace.const_get(name) }.grep(Class)
    unbuilt(classes) do
      pair = Pair.run(Pair.client(identities: [Pair.client_identity]), { config: Pair.server_config(client_auth: :required) })
      assert pair.client.complete?
      assert pair.server.complete?
    end
  end

  # Runs the block with `new` of each class failing the test, then gives
  # the classes back their own.
  def unbuilt(classes)
    test = self
    classes.each { |klass| klass.define_singleton_method(:new) { |*, **| test.flunk "#{klass} was built" } }
    yield
  ensure
    classes.each { |klass| klass.singleton_class.remove_method(:new) }
  end
end
