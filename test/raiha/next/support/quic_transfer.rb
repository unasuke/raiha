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

  # A network with a client of `client_config`, issuing connection IDs
  # with `client_issuer` as an Endpoint's would, and a server's Endpoint of
  # `server_config`, at SERVER and `server_addresses` besides, linked by
  # `model` both ways, each wrapped with its application's step: the
  # client's is given the client Connection, the server's the Test::Server.
  # After its step, each application takes its connections' events, as it
  # has to. Gives [network, client, server].
  def transfer_network(seed: 1, model: nil, forward: model, reverse: model, client_config: QUIC::Config.new,
    client_issuer: nil, server_config: QUIC::Config.new, server_addresses: [], client_tracer: nil, server_tracer: nil, client_wake: nil,
    server_wake: nil, client_step:, server_step:)
    net = Test::Network.new(seed:)
    client = client_connection(config: client_config, tracer: client_tracer, issuer: client_issuer)
    tls_config = server_config_for_transfer
    keyring = TLS::Keyring.server(config: tls_config, identities: [NextTLSPair.server_identity], random: Random.new(2))
    endpoint = QUIC::Endpoint.server(config: server_config, random: Random.new(seed), time: NOW, now: 0.0)
    server = Test::Server.new(endpoint, tls_config:, keyring:, tracer: server_tracer)
    client_node = net.add(App.new(client, wake: client_wake) { |now|
      client_step.call(client, now)
      client.each_event { nil }
    }, address: CLIENT)
    server_node = net.add(App.new(server, wake: server_wake) { |now|
      server_step.call(server, now)
      server.connections.each { |connection| connection.each_event { nil } }
    }, address: SERVER)
    server_addresses.each { |address| net.add_address(server_node, address:) }
    net.link(client_node, server_node, forward:, reverse:)
    [net, client, server]
  end

  def server_config_for_transfer = server_config

  # The client asks for `size` bytes on its first stream once the handshake
  # is confirmed, and reads them as they come; the server writes them as
  # fast as the stream takes them. `network` is as transfer_network takes
  # it. Gives the network, the client, the server and the client's reads, as
  # [time, bytes read so far].
  def download(size, **network)
    reads = []
    request = nil
    asked = false
    sent = 0
    client_step = lambda do |client, now|
      if client.handshake_confirmed? && request.nil?
        request = client.open_stream
        client.stream_write(request || raise, "GET", fin: true)
      end
      next unless request
      data, = drain(client, request)
      reads << [now, (reads.last&.last || 0) + data.bytesize] unless data.empty?
    end
    server_step = lambda do |server, _now|
      server.connections.each do |connection|
        next unless connection.handshake_complete? && !connection.closing? && !connection.draining? && !connection.closed?
        asked ||= connection.readable_streams.include?(0) && !drain(connection, 0).nil?
        next unless asked
        while sent < size
          chunk = [size - sent, 65_536].min
          taken = connection.stream_write(0, "x".b * chunk, fin: sent + chunk == size)
          sent += taken
          break if taken < chunk
        end
      end
    end
    net, client, server = transfer_network(client_step:, server_step:, **network)
    [net, client, server, reads]
  end

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
