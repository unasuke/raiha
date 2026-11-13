#!/usr/bin/env ruby
# frozen_string_literal: true

# A TLS 1.3 client over TCP of the next release of raiha (TLS::TCP::Socket)
# for TLS-Anvil's client tests: TLS-Anvil runs a trigger before each
# handshake, an HTTP request to `trigger_port` here, and the client then
# connects to TLS-Anvil's server at `anvil_port`, sends a GET and reads
# until the server closes. TLS-Anvil's certificate is its own, so the
# client takes any (TLS::Verifier::None). What fails in one connection is
# printed and the client goes on.
#
# Usage:
#   bundle exec ruby script/tls_anvil_client.rb [trigger_port] [anvil_port]   (4477 and 4478 by default)

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "socket"
require "raiha/tls"

TLS = Raiha::Next::TLS

trigger_port = (ARGV[0] || 4477).to_i
anvil_port = (ARGV[1] || 4478).to_i
config = TLS::Config.client

trigger = TCPServer.new("127.0.0.1", trigger_port)
$stderr.puts "TLS-Anvil client trigger on port #{trigger_port}, connecting to #{anvil_port}"

loop do
  request = trigger.accept
  request.readpartial(4096) rescue nil
  request.write("HTTP/1.0 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
  request.close
  Thread.new do
    keyring = TLS::Keyring.client(config:, verifier: TLS::Verifier::None.new)
    TLS::TCP::Socket.connect("127.0.0.1", anvil_port, server_name: "localhost", config:, keyring:) do |socket|
      socket.write("GET / HTTP/1.0\r\n\r\n")
      nil while socket.read(16_384)
    end
  rescue StandardError => e
    $stderr.puts "  Connection error: #{e.class}: #{e.message}"
  end
end
