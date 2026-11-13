# A richer qlog than qlog_output.rb: one connection of the runtime on the
# loopback interface carries ROUNDTRIPS echoes, each on a stream of its
# own, of 512 random bytes, so that the traces in
# tmp/raiha-example-qlog-roundtrips show every packet sent and received
# over many round trips, for qlog tools to draw. ROUNDTRIPS is 20 unless
# the environment says otherwise; the server lets a client open 100
# streams.
#
# Usage:
#   bundle exec ruby -Ilib examples/qlog_roundtrips.rb
#   ROUNDTRIPS=50 bundle exec ruby -Ilib examples/qlog_roundtrips.rb
#
# Expected output:
#   20 roundtrips OK (512 bytes each)
#   qlog written: 1 client and 1 server trace in tmp/raiha-example-qlog-roundtrips

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
QLOG_DIR = "tmp/raiha-example-qlog-roundtrips"
ROUNDTRIPS = Integer(ENV.fetch("ROUNDTRIPS", 20))
PAYLOAD_SIZE = 512

FileUtils.rm_rf(QLOG_DIR)
FileUtils.mkdir_p(QLOG_DIR)
server_tls = TLS::Config.server(profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY)
server = Runtime::Server.new(config: QUIC::Config.new, tls_config: server_tls,
  keyring: TLS::Keyring.server(config: server_tls, identities: [ExampleCertificate.identity]), host: "127.0.0.1", port: 0,
  qlog_dir: QLOG_DIR)
client_tls = TLS::Config.client(trust_anchors: [ExampleCertificate.ca_der], profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY)
matched = 0

Async do
  running = Async { server.run { |session| session.each_stream { |stream| (stream << stream.read).close_write } } }
  sleep 0.01 until server.local_address
  Runtime::Client.connect("127.0.0.1", server.local_address[1], server_name: "localhost", config: QUIC::Config.new, tls_config: client_tls,
    keyring: TLS::Keyring.client(config: client_tls), qlog_dir: QLOG_DIR) do |session|
    ROUNDTRIPS.times do
      payload = SecureRandom.random_bytes(PAYLOAD_SIZE)
      stream = session.open_stream
      stream << payload
      stream.close_write
      matched += 1 if stream.read == payload
    end
  end
  server.stop(timeout: 1)
  running.wait
end

raise "#{ROUNDTRIPS - matched} of #{ROUNDTRIPS} echoes did not match" unless matched == ROUNDTRIPS

puts "#{ROUNDTRIPS} roundtrips OK (#{PAYLOAD_SIZE} bytes each)"
clients = Dir.glob(File.join(QLOG_DIR, "*client*.sqlog")).size
servers = Dir.glob(File.join(QLOG_DIR, "*server*.sqlog")).size
puts "qlog written: #{clients} client and #{servers} server trace in #{QLOG_DIR}"
