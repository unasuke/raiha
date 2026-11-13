# A server and a client of the runtime on the loopback interface, each
# writing a qlog of its connection to tmp/raiha-example-qlog: the
# handshake and an echo on a stream, as in high_level_loopback.rb. Each
# trace is a JSON-SEQ file (.sqlog), which qvis and other qlog tools read:
# the server's named by the connection ID the client first chose, the
# client's by the time it connected.
#
# Usage:
#   bundle exec ruby -Ilib examples/qlog_output.rb
#
# Expected output:
#   qlog written: 1 client and 1 server trace in tmp/raiha-example-qlog

require "raiha/runtime"
# The scheduler of async reads with IO::Buffer, which Ruby 4.0 warns is
# experimental.
Warning[:experimental] = false
require "async"
require "fileutils"
require "securerandom"
require_relative "_certificate"

Runtime = Raiha::Next::Runtime
QUIC = Raiha::Next::QUIC
TLS = Raiha::Next::TLS
REGISTRY = TLS::Extension::Registry::BUILTIN.with(QUIC::TransportParameters::Extension)
ALPN = ["hq-interop"].freeze
QLOG_DIR = "tmp/raiha-example-qlog"

FileUtils.rm_rf(QLOG_DIR)
FileUtils.mkdir_p(QLOG_DIR)
server_tls = TLS::Config.server(profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY)
server = Runtime::Server.new(config: QUIC::Config.new, tls_config: server_tls,
  keyring: TLS::Keyring.server(config: server_tls, identities: [ExampleCertificate.identity]), host: "127.0.0.1", port: 0,
  qlog_dir: QLOG_DIR)
client_tls = TLS::Config.client(trust_anchors: [ExampleCertificate.ca_der], profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY)
payload = SecureRandom.random_bytes(256)
echoed = nil

Async do
  running = Async { server.run { |session| session.each_stream { |stream| (stream << stream.read).close_write } } }
  sleep 0.01 until server.local_address
  Runtime::Client.connect("127.0.0.1", server.local_address[1], server_name: "localhost", config: QUIC::Config.new, tls_config: client_tls,
    keyring: TLS::Keyring.client(config: client_tls), qlog_dir: QLOG_DIR) do |session|
    stream = session.open_stream
    stream << payload
    stream.close_write
    echoed = stream.read
  end
  server.stop(timeout: 1)
  running.wait
end

raise "Echo payload mismatch" unless echoed == payload

clients = Dir.glob(File.join(QLOG_DIR, "*client*.sqlog")).size
servers = Dir.glob(File.join(QLOG_DIR, "*server*.sqlog")).size
puts "qlog written: #{clients} client and #{servers} server trace in #{QLOG_DIR}"
