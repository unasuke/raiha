require "support/threaded_owner"
require "support/runtime_http3"

# HTTP/3 for the tests of the runtime on threads: TLS settings with "h3"
# for ALPN, and RuntimeHTTP3::Answerer attached to each Session of a
# Threaded::Server, which calls it under the core lock as the Session's
# protocol.
module ThreadedHTTP3
  include ThreadedOwner

  HTTP3 = Raiha::HTTP3
  H3 = ["h3"].freeze
  Answerer = RuntimeHTTP3::Answerer

  def h3_server_config = TLSPair.server_config(profile: TLS::Profile::QUIC, alpn: H3, registry: REGISTRY)

  def h3_client_config = TLSPair.client_config(profile: TLS::Profile::QUIC, alpn: H3, registry: REGISTRY)

  # A Threaded::Server on a free port answering with `bodies`, for the
  # block, which is given its port and the server's sessions as they come.
  def answering(bodies)
    sessions = Queue.new
    tls = h3_server_config
    server = Threaded::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1", port: 0)
    running = Thread.new do
      server.run do |session|
        sessions << session
        Answerer.new(session, bodies)
        sleep 0.01 until session.closed?
      end
    end
    sleep 0.01 until server.local_address
    yield server.local_address.fetch(1), sessions
  ensure
    server&.stop(timeout: 1)
    running&.join(10)
  end

  # A Threaded::Session of a client connected to `port` with "h3", for the
  # block.
  def h3_connect(port, **options, &)
    tls = h3_client_config
    Threaded::Client.connect("127.0.0.1", port, config: QUIC::Config.new, tls_config: tls, keyring: client_keyring(config: tls),
      server_name: "localhost", **options, &)
  end
end
