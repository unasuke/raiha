# A QUIC handshake between a client and a server Connection in one
# process, with no socket: each side's datagrams are handed to the other
# by hand, at a time the example makes up. A Connection never reads a clock
# or touches the network, so this is all a test of the protocol needs.
#
# Usage:
#   bundle exec ruby -Ilib examples/next/in_memory_handshake.rb
#
# Expected output:
#   Handshake complete (client: true, server: true)

require "raiha/next/quic"
require_relative "_certificate"

QUIC = Raiha::Next::QUIC
TLS = Raiha::Next::TLS
REGISTRY = TLS::Extension::Registry::BUILTIN.with(QUIC::TransportParameters::Extension)
ALPN = ["hq-interop"].freeze
CLIENT = ["192.0.2.1", 50_000].freeze
SERVER = ["192.0.2.2", 443].freeze

client_tls = TLS::Config.client(trust_anchors: [ExampleCertificate.ca_der], profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY)
server_tls = TLS::Config.server(profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY)
now = 0.0
client = QUIC::Connection.client(config: QUIC::Config.new, tls_config: client_tls, keyring: TLS::Keyring.client(config: client_tls),
  server_name: "localhost", remote: SERVER, time: Time.now, now:)
server = QUIC::Connection.server(config: QUIC::Config.new, tls_config: server_tls,
  keyring: TLS::Keyring.server(config: server_tls, identities: [ExampleCertificate.identity]), time: Time.now, now:)

# A millisecond each way, until both have completed the handshake.
20.times do
  break if client.handshake_complete? && server.handshake_complete?
  client.each_transmit(now:) { |transmit| server.receive(transmit.payload, from: CLIENT, now:) }
  server.each_transmit(now:) { |transmit| client.receive(transmit.payload, from: SERVER, now:) }
  now += 0.001
end

puts "Handshake complete (client: #{client.handshake_complete?}, server: #{server.handshake_complete?})"
