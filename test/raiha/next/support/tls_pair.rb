require "raiha/next/tls"
require "raiha/next/support/test_pki"

# A client and a server Machine of the next release of raiha, built from a
# test PKI and run against each other with nothing in between.
module NextTLSPair
  TLS = Raiha::Next::TLS
  PKI = NextTestPKI
  NOW = PKI::NOW

  Pair = Data.define(:client, :server, :client_outputs, :server_outputs)

  module_function

  def ca = @ca ||= PKI.ca

  def server_identity(names: ["DNS:localhost"], key: PKI.key(:p256))
    leaf = PKI.leaf(ca, names:, key:)
    TLS::Keyring::Identity.new(cert_der: [leaf.der, ca.der], key_der: leaf.key_der)
  end

  def client_identity(key: PKI.key(:client))
    leaf = PKI.leaf(ca, names: [], common_name: "client", key:, purpose: "clientAuth", serial: 3)
    TLS::Keyring::Identity.new(cert_der: [leaf.der, ca.der], key_der: leaf.key_der)
  end

  def client_config(**options) = TLS::Config.client(trust_anchors: [ca.der], **options)

  def server_config(**options) = TLS::Config.server(trust_anchors: [ca.der], **options)

  def client(config: client_config, keyring: nil, server_name: "localhost", extensions: [], tracer: nil, now: NOW, **keyring_options)
    keyring ||= TLS::Keyring.client(config:, **keyring_options)
    TLS::Handshake::Machine.client(config:, keyring:, server_name:, extensions:, tracer:, now:)
  end

  def server_keyring(config: server_config, identities: [server_identity], **options)
    TLS::Keyring.server(config:, identities:, **options)
  end

  def server(client_hello, config: server_config, keyring: nil, extensions: [], tracer: nil, now: NOW)
    keyring ||= server_keyring(config:)
    TLS::Handshake::Machine.server(config:, keyring:, client_hello:, extensions:, tracer:, now:)
  end

  # Passes Messages each way until both complete or one fails, and returns
  # every output each side produced, in order.
  def run(client, server_options = {}, now: NOW)
    client_outputs = client.outputs
    hello = client_outputs.find { |output| output.is_a?(TLS::Output::Message) } or raise "no ClientHello"
    server = server(hello.bytes, **server_options, now:)
    server_outputs = []
    20.times do
      sent = server.outputs
      server_outputs.concat(sent)
      deliver(sent, client, now:)
      received = client.outputs
      client_outputs.concat(received)
      deliver(received, server, now:)
      break if (client.complete? && server.complete?) || client.failed? || server.failed?
    end
    server_outputs.concat(server.outputs)
    client_outputs.concat(client.outputs)
    Pair.new(client:, server:, client_outputs:, server_outputs:)
  end

  def deliver(outputs, machine, now: NOW)
    outputs.each do |output|
      machine.receive(output.bytes, epoch: output.epoch, now:) if output.is_a?(TLS::Output::Message)
    end
  end

  # [class, epoch, direction] of each output, for comparing sequences.
  def shape(outputs)
    outputs.map do |output|
      case output
      when TLS::Output::Secret then [:secret, output.epoch, output.direction]
      when TLS::Output::Message then [:message, output.epoch, output.bytes.getbyte(0)]
      when TLS::Output::Alert then [:alert, output.epoch, output.description]
      end
    end
  end
end
