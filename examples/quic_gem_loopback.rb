# A client of the quic gem (github: unasuke/quic-ruby, ngtcp2 and picotls
# under a thin binding) against the runtime's server on the loopback
# interface: the client completes the handshake, sends a payload on a
# stream of its own, and the server answers it with "ECHO:" and the
# payload.
#
# The client runs in a process of its own (test/support/quic_gem_echo_client.rb):
# the quic gem carries a TLS library of its own, which crashes Ruby when
# loaded beside Ruby's openssl, which raiha needs.
#
# The quic gem is in the optional :interop group of the bundle, so no test
# runs this example. Run with:
#   bundle install --with interop
#   bundle exec ruby -Ilib examples/quic_gem_loopback.rb
#
# Expected output:
#   The quic gem's client (ngtcp2) connected, stream echo OK

require "raiha/runtime"
# The scheduler of async reads with IO::Buffer, which Ruby 4.0 warns is
# experimental.
Warning[:experimental] = false
require "async"
require "securerandom"
require_relative "_certificate"

Runtime = Raiha::Runtime
QUIC = Raiha::QUIC
TLS = Raiha::TLS
REGISTRY = TLS::Extension::Registry::BUILTIN.with(QUIC::TransportParameters::Extension)
ALPN = "raiha-interop"
ECHO_CLIENT = File.expand_path("../test/support/quic_gem_echo_client.rb", __dir__)

server_tls = TLS::Config.server(profile: TLS::Profile::QUIC, alpn: [ALPN], registry: REGISTRY)
server = Runtime::Server.new(config: QUIC::Config.new, tls_config: server_tls,
  keyring: TLS::Keyring.server(config: server_tls, identities: [ExampleCertificate.identity]), host: "127.0.0.1", port: 0)
payload = SecureRandom.hex(16)
output = nil
status = nil

Async do
  running = Async { server.run { |session| session.each_stream { |stream| (stream << "ECHO:" << stream.read).close_write } } }
  sleep 0.01 until server.local_address
  # The client's process, waited for in a thread so that the server's
  # fiber goes on.
  output, status = Thread.new do
    reader, writer = IO.pipe
    pid = Process.spawn("bundle", "exec", "ruby", ECHO_CLIENT, "--host", "127.0.0.1", "--port", server.local_address[1].to_s, "--alpn", ALPN,
      "--data", payload, out: writer, err: writer)
    writer.close
    text = reader.read
    [text, Process.wait2(pid).last]
  end.value
  server.stop(timeout: 1)
  running.wait
end

unless status.success? && output.include?("HANDSHAKE_COMPLETE") && output.include?("ECHO_OK")
  raise "the quic gem's client failed (#{status.inspect}):\n#{output}"
end

puts "The quic gem's client (ngtcp2) connected, stream echo OK"
