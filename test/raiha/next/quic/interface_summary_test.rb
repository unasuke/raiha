require "raiha/next/test_helper"
require "raiha/next/support/quic_tls"

# What the TLS Machine puts out for a QUIC connection, step by step, set
# against the figure of RFC 9001 "TLS Interface Summary". Each message goes
# at the level the figure has it at, and each key is there by the time the
# figure needs it; within a step the keys come before the messages, as a
# Secret is when its keys may be used and a message's epoch is what it is
# sent under. RFC 9001 lets the order within a step differ. 0-RTT, which
# the figure also shows, comes with resumption.
class RaihaNextQUICInterfaceSummaryTest < Minitest::Test
  include NextQUICTLS

  CLIENT_HELLO = 1
  SERVER_HELLO = 2
  ENCRYPTED_EXTENSIONS = 8
  CERTIFICATE = 11
  CERTIFICATE_VERIFY = 15
  FINISHED = 20

  def transport_parameters(cid)
    TLS::Extension::Opaque.new(type: QUIC::TLSBinding::TRANSPORT_PARAMETERS,
      data: QUIC::TransportParameters.new(initial_source_connection_id: cid).encode)
  end

  # The classes of the events of `machine` since last asked.
  def events(machine) = [].tap { |all| machine.each_event { all << _1.class } }

  def messages(outputs, epoch) = outputs.select { _1.is_a?(TLS::Output::Message) && _1.epoch == epoch }

  def test_the_steps_of_a_handshake
    client_tls = client_config
    server_tls = server_config
    client = NextTLSPair.client(config: client_tls, extensions: [transport_parameters("c".b * 8)])
    # Client: "Get Handshake", the ClientHello in an Initial packet.
    hello = client.outputs
    assert_equal [[:message, :initial, CLIENT_HELLO]], NextTLSPair.shape(hello)

    server = TLS::Handshake::Machine.server(config: server_tls, keyring: server_keyring(config: server_tls),
      extensions: [transport_parameters("s".b * 8)], now: NOW)
    server.receive(hello.first.bytes, epoch: :initial, now: NOW)
    server_flight = server.outputs
    events(server)
    # Server: "Handshake Received", "Get Handshake" for the ServerHello in an
    # Initial packet, "Install Handshake keys", "Get Handshake" for the rest
    # in Handshake packets, and "Install tx 1-RTT keys".
    assert_equal [
      [:secret, :handshake, :read], [:secret, :handshake, :write], [:secret, :application, :write],
      [:message, :initial, SERVER_HELLO],
      [:message, :handshake, ENCRYPTED_EXTENSIONS], [:message, :handshake, CERTIFICATE], [:message, :handshake, CERTIFICATE_VERIFY],
      [:message, :handshake, FINISHED]
    ], NextTLSPair.shape(server_flight)

    # Client: "Handshake Received (Initial)", "Install Handshake keys".
    NextTLSPair.deliver(messages(server_flight, :initial), client)
    assert_equal [[:secret, :handshake, :read], [:secret, :handshake, :write]], NextTLSPair.shape(client.outputs)
    assert_empty events(client)

    # Client: "Handshake Received (Handshake)", "Get Handshake" for its
    # Finished in a Handshake packet, "Handshake Complete", "Install 1-RTT
    # keys".
    NextTLSPair.deliver(messages(server_flight, :handshake), client)
    client_flight = client.outputs
    assert_equal [[:secret, :application, :read], [:secret, :application, :write], [:message, :handshake, FINISHED]],
      NextTLSPair.shape(client_flight)
    assert_includes events(client), TLS::Event::HandshakeComplete

    # Server: "Handshake Received", "Handshake Complete", and only now
    # "Install rx 1-RTT keys" (RFC 9001 "Receiving Out-of-Order Protected
    # Packets": no 1-RTT packet before the handshake is complete).
    NextTLSPair.deliver(client_flight, server)
    assert_equal [[:secret, :application, :read]], NextTLSPair.shape(server.outputs)
    assert_equal [TLS::Event::HandshakeComplete], events(server)
  end
end
