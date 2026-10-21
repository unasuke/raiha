require "raiha/next/support/quic_pair"
require "raiha/next/quic/test"

# Applications over streams on a Test::Network, on virtual time: a node is
# wrapped so that the application's step runs whenever the connection may
# have something new for it, after a datagram or a timer and before
# sending, so that what it reads and writes goes at once.
module NextQUICTransfer
  include NextQUICPair

  Test = QUIC::Test

  class App
    # `wake`, when given, says when the application wants to run next.
    def initialize(node, wake: nil, &step)
      @node = node
      @wake = wake
      @step = step
    end

    def receive(payload, from:, to:, ecn:, now:)
      @node.receive(payload, from:, to:, ecn:, now:)
      @step.call(now)
    end

    def each_transmit(now:, &)
      @step.call(now)
      @node.each_transmit(now:, &)
    end

    def next_timeout = [@node.next_timeout, @wake&.call].compact.min

    def handle_timeout(now:)
      @node.handle_timeout(now:)
      @step.call(now)
    end
  end

  module_function

  # A network with a client of `client_config` and a server's Endpoint of
  # `server_config`, linked by `model` both ways, each wrapped with its
  # application's step: the client's is given the client Connection, the
  # server's the Test::Server. Gives [network, client, server].
  def transfer_network(seed: 1, model: nil, forward: model, reverse: model, client_config: QUIC::Config.new,
    server_config: QUIC::Config.new, server_tracer: nil, client_wake: nil, server_wake: nil, client_step:, server_step:)
    net = Test::Network.new(seed:)
    client = client_connection(config: client_config)
    tls_config = server_config_for_transfer
    keyring = TLS::Keyring.server(config: tls_config, identities: [NextTLSPair.server_identity], random: Random.new(2))
    endpoint = QUIC::Endpoint.server(config: server_config, random: Random.new(seed), time: NOW, now: 0.0)
    server = Test::Server.new(endpoint, tls_config:, keyring:, tracer: server_tracer)
    client_node = net.add(App.new(client, wake: client_wake) { |now| client_step.call(client, now) }, address: CLIENT)
    server_node = net.add(App.new(server, wake: server_wake) { |now| server_step.call(server, now) }, address: SERVER)
    net.link(client_node, server_node, forward:, reverse:)
    [net, client, server]
  end

  def server_config_for_transfer = server_config

  # All `stream_id` has to read now, and whether it has ended.
  def drain(connection, stream_id)
    data = "".b
    while (chunk = connection.stream_read(stream_id, 1 << 20))
      return [data, false] if chunk.empty?
      data << chunk
    end
    [data, true]
  end
end
