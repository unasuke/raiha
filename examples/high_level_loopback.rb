# A server and a client of the runtime of the next release of raiha on the
# loopback interface, in fibers of the scheduler of the async gem: the
# server takes each connection and echoes each stream its client opens,
# and the client sends a payload on a stream of its own and reads it back.
# No loop of the application's own: the runtime waits on the sockets and
# the timers, and each call blocks only the fiber that makes it.
#
# Usage:
#   bundle exec ruby -Ilib examples/high_level_loopback.rb
#
# Expected output:
#   Raiha::Next::Runtime::Server accepted 1 connection, stream echo OK

require "raiha/runtime"
# The scheduler of async reads with IO::Buffer, which Ruby 4.0 warns is
# experimental.
Warning[:experimental] = false
require "async"
require "securerandom"
require_relative "_certificate"

Runtime = Raiha::Next::Runtime
QUIC = Raiha::Next::QUIC
TLS = Raiha::Next::TLS
REGISTRY = TLS::Extension::Registry::BUILTIN.with(QUIC::TransportParameters::Extension)
ALPN = ["hq-interop"].freeze

server_tls = TLS::Config.server(profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY)
server = Runtime::Server.new(config: QUIC::Config.new, tls_config: server_tls,
  keyring: TLS::Keyring.server(config: server_tls, identities: [ExampleCertificate.identity]), host: "127.0.0.1", port: 0)
client_tls = TLS::Config.client(trust_anchors: [ExampleCertificate.ca_der], profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY)
payload = SecureRandom.random_bytes(256)
accepted = 0
echoed = nil

Async do
  running = Async do
    server.run do |session|
      accepted += 1
      session.each_stream { |stream| (stream << stream.read).close_write }
    end
  end
  sleep 0.01 until server.local_address

  Runtime::Client.connect("127.0.0.1", server.local_address[1], server_name: "localhost", config: QUIC::Config.new, tls_config: client_tls,
    keyring: TLS::Keyring.client(config: client_tls)) do |session|
    stream = session.open_stream
    stream << payload
    stream.close_write
    echoed = stream.read
  end

  server.stop(timeout: 1)
  running.wait
end

raise "Echo payload mismatch" unless echoed == payload

puts "Raiha::Next::Runtime::Server accepted #{accepted} connection, stream echo OK"
