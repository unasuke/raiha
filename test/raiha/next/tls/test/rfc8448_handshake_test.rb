require "raiha/next/test_helper"
require "raiha/next/tls/test"

# RFC 8448 sections 3, 5 and 6, played by the Machine in both roles, and
# section 4 by its client, against the trace's messages: every Secret it outputs, and every message it
# builds itself, byte for byte. Messages NSS sent that this implementation
# never builds are replaced by the trace's bytes (Test::RFC8448.machine).
#
# The output sequences here are the state machine design's table of outputs
# for 1-RTT, HelloRetryRequest and client authentication, checked against
# the traces.
class RaihaNextTLSRFC8448HandshakeTest < Minitest::Test
  TLS = Raiha::Next::TLS
  RFC8448 = TLS::Test::RFC8448
  S = RFC8448::Simple1RTT
  H = RFC8448::HelloRetryRequest
  A = RFC8448::ClientAuthentication
  NOW = Time.utc(2018, 1, 1)

  def machine(section, role) = RFC8448.machine(section, role, now: NOW)

  def receive(machine, epoch, *messages)
    machine.receive(messages.join.b, epoch:, now: NOW)
    refute machine.failed?, "failed with #{machine.alert}"
    machine.outputs
  end

  # Each output as the trace's value it must equal: a Secret by epoch and
  # direction, a Message by its bytes.
  def assert_outputs(expected, outputs)
    actual = outputs.map do |output|
      case output
      when TLS::Output::Secret then [output.epoch, output.direction, output.secret]
      when TLS::Output::Message then [output.epoch, output.bytes]
      else output
      end
    end
    assert_equal expected.size, actual.size, actual.map { |entry| entry.first(2) }.inspect
    expected.zip(actual).each_with_index do |(want, got), i|
      assert_equal want, got, "output #{i}"
    end
  end

  def test_simple_1rtt_client
    client = machine(:simple_1rtt, :client)
    assert_outputs [[:initial, S::CLIENT_HELLO]], client.outputs
    assert_outputs [[:handshake, :read, S::SERVER_HANDSHAKE_TRAFFIC_SECRET], [:handshake, :write, S::CLIENT_HANDSHAKE_TRAFFIC_SECRET]],
      receive(client, :initial, S::SERVER_HELLO)
    outputs = receive(client, :handshake, S::ENCRYPTED_EXTENSIONS, S::CERTIFICATE, S::CERTIFICATE_VERIFY, S::SERVER_FINISHED)
    assert_outputs [
      [:application, :read, S::SERVER_APPLICATION_TRAFFIC_SECRET_0],
      [:application, :write, S::CLIENT_APPLICATION_TRAFFIC_SECRET_0],
      [:handshake, S::CLIENT_FINISHED]
    ], outputs
    assert client.complete?
  end

  # Section 4: the binder over NSS's ClientHello, the 0-RTT key over the
  # whole of it, then EndOfEarlyData under that key before the Finished.
  def test_resumed_0rtt_client
    r = RFC8448::Resumed0RTT
    client = machine(:resumed_0rtt, :client)
    assert_outputs [[:early_data, :write, r::CLIENT_EARLY_TRAFFIC_SECRET], [:initial, r::CLIENT_HELLO]], client.outputs
    assert_outputs [[:handshake, :read, r::SERVER_HANDSHAKE_TRAFFIC_SECRET], [:handshake, :write, r::CLIENT_HANDSHAKE_TRAFFIC_SECRET]],
      receive(client, :initial, r::SERVER_HELLO)
    assert_equal :early_data, client.write_epoch
    assert_outputs [
      [:application, :read, r::SERVER_APPLICATION_TRAFFIC_SECRET_0],
      [:application, :write, r::CLIENT_APPLICATION_TRAFFIC_SECRET_0],
      [:early_data, r::END_OF_EARLY_DATA],
      [:handshake, r::CLIENT_FINISHED]
    ], receive(client, :handshake, r::ENCRYPTED_EXTENSIONS, r::SERVER_FINISHED)
    assert client.complete?
    complete = client.each_event.grep(TLS::Event::HandshakeComplete).first
    assert complete.resumed && complete.early_data_accepted
  end

  def test_simple_1rtt_server
    server = machine(:simple_1rtt, :server)
    assert_outputs [
      [:handshake, :read, S::CLIENT_HANDSHAKE_TRAFFIC_SECRET],
      [:handshake, :write, S::SERVER_HANDSHAKE_TRAFFIC_SECRET],
      [:application, :write, S::SERVER_APPLICATION_TRAFFIC_SECRET_0],
      [:initial, S::SERVER_HELLO],
      [:handshake, S::ENCRYPTED_EXTENSIONS], [:handshake, S::CERTIFICATE], [:handshake, S::CERTIFICATE_VERIFY],
      [:handshake, S::SERVER_FINISHED]
    ], receive(server, :initial, S::CLIENT_HELLO)
    assert_outputs [[:application, :read, S::CLIENT_APPLICATION_TRAFFIC_SECRET_0]], receive(server, :handshake, S::CLIENT_FINISHED)
    assert server.complete?
  end

  def test_hello_retry_request_client
    client = machine(:hello_retry_request, :client)
    assert_outputs [[:initial, H::CLIENT_HELLO_1]], client.outputs
    assert_outputs [[:initial, H::CLIENT_HELLO_2]], receive(client, :initial, H::HELLO_RETRY_REQUEST)
    assert_outputs [[:handshake, :read, H::SERVER_HANDSHAKE_TRAFFIC_SECRET], [:handshake, :write, H::CLIENT_HANDSHAKE_TRAFFIC_SECRET]],
      receive(client, :initial, H::SERVER_HELLO)
    outputs = receive(client, :handshake, H::ENCRYPTED_EXTENSIONS, H::CERTIFICATE, H::CERTIFICATE_VERIFY, H::SERVER_FINISHED)
    assert_outputs [
      [:application, :read, H::SERVER_APPLICATION_TRAFFIC_SECRET_0],
      [:application, :write, H::CLIENT_APPLICATION_TRAFFIC_SECRET_0],
      [:handshake, H::CLIENT_FINISHED]
    ], outputs
    assert client.complete?
  end

  # The second ClientHello adds padding and puts the cookie mid-list; both
  # are changes RFC 9846 allows.
  def test_hello_retry_request_server
    server = machine(:hello_retry_request, :server)
    assert_outputs [[:initial, H::HELLO_RETRY_REQUEST]], receive(server, :initial, H::CLIENT_HELLO_1)
    assert_outputs [
      [:handshake, :read, H::CLIENT_HANDSHAKE_TRAFFIC_SECRET],
      [:handshake, :write, H::SERVER_HANDSHAKE_TRAFFIC_SECRET],
      [:application, :write, H::SERVER_APPLICATION_TRAFFIC_SECRET_0],
      [:initial, H::SERVER_HELLO],
      [:handshake, H::ENCRYPTED_EXTENSIONS], [:handshake, H::CERTIFICATE], [:handshake, H::CERTIFICATE_VERIFY],
      [:handshake, H::SERVER_FINISHED]
    ], receive(server, :initial, H::CLIENT_HELLO_2)
    assert_outputs [[:application, :read, H::CLIENT_APPLICATION_TRAFFIC_SECRET_0]], receive(server, :handshake, H::CLIENT_FINISHED)
    assert server.complete?
  end

  def test_client_authentication_client
    client = machine(:client_authentication, :client)
    assert_outputs [[:initial, A::CLIENT_HELLO]], client.outputs
    assert_outputs [[:handshake, :read, A::SERVER_HANDSHAKE_TRAFFIC_SECRET], [:handshake, :write, A::CLIENT_HANDSHAKE_TRAFFIC_SECRET]],
      receive(client, :initial, A::SERVER_HELLO)
    outputs = receive(client, :handshake, A::ENCRYPTED_EXTENSIONS, A::CERTIFICATE_REQUEST, A::SERVER_CERTIFICATE,
      A::SERVER_CERTIFICATE_VERIFY, A::SERVER_FINISHED)
    assert_outputs [
      [:application, :read, A::SERVER_APPLICATION_TRAFFIC_SECRET_0],
      [:application, :write, A::CLIENT_APPLICATION_TRAFFIC_SECRET_0],
      [:handshake, A::CLIENT_CERTIFICATE], [:handshake, A::CLIENT_CERTIFICATE_VERIFY], [:handshake, A::CLIENT_FINISHED]
    ], outputs
    assert client.complete?
  end

  def test_client_authentication_server
    server = machine(:client_authentication, :server)
    assert_outputs [
      [:handshake, :read, A::CLIENT_HANDSHAKE_TRAFFIC_SECRET],
      [:handshake, :write, A::SERVER_HANDSHAKE_TRAFFIC_SECRET],
      [:application, :write, A::SERVER_APPLICATION_TRAFFIC_SECRET_0],
      [:initial, A::SERVER_HELLO],
      [:handshake, A::ENCRYPTED_EXTENSIONS], [:handshake, A::CERTIFICATE_REQUEST], [:handshake, A::SERVER_CERTIFICATE],
      [:handshake, A::SERVER_CERTIFICATE_VERIFY], [:handshake, A::SERVER_FINISHED]
    ], receive(server, :initial, A::CLIENT_HELLO)
    outputs = receive(server, :handshake, A::CLIENT_CERTIFICATE, A::CLIENT_CERTIFICATE_VERIFY, A::CLIENT_FINISHED)
    assert_outputs [[:application, :read, A::CLIENT_APPLICATION_TRAFFIC_SECRET_0]], outputs
    assert server.complete?
    done = server.each_event.grep(TLS::Event::HandshakeComplete).first
    assert_equal 1, done.peer_certificates.size
  end

  # A Finished that does not verify fails with decrypt_error, so the
  # comparisons above are not passing by accident.
  def test_tampered_finished_fails
    client = machine(:simple_1rtt, :client)
    client.outputs
    client.receive(S::SERVER_HELLO, epoch: :initial, now: NOW)
    tampered = S::SERVER_FINISHED.dup
    tampered.setbyte(-1, tampered.getbyte(-1) ^ 1)
    client.receive(S::ENCRYPTED_EXTENSIONS + S::CERTIFICATE + S::CERTIFICATE_VERIFY + tampered, epoch: :handshake, now: NOW)
    assert_equal :decrypt_error, client.alert
  end
end
