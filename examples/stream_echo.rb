# A stream between a client and a server Connection in one process, with
# no socket: once the handshake is done, the client sends 256 random bytes
# on a stream of its own and ends it; the server reads them as they come
# (Event::StreamReadable) and sends the same bytes back on that stream;
# the client reads them back. Each side's datagrams are handed to the
# other by hand.
#
# Usage:
#   bundle exec ruby -Ilib examples/stream_echo.rb
#
# Expected output:
#   Echo matched: 256 bytes

require "raiha/quic"
require "securerandom"
require_relative "_certificate"

QUIC = Raiha::QUIC
TLS = Raiha::TLS
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

# Passes what each side has to send to the other, and moves the time on.
exchange = lambda do
  client.each_transmit(now:) { |transmit| server.receive(transmit.payload, from: CLIENT, now:) }
  server.each_transmit(now:) { |transmit| client.receive(transmit.payload, from: SERVER, now:) }
  now += 0.001
end

exchange.call until client.handshake_confirmed? && server.handshake_complete?

payload = SecureRandom.random_bytes(256)
stream_id = client.open_stream
client.stream_write(stream_id, payload, fin: true)

# The server echoes what it reads on each stream that becomes readable,
# and ends the stream once the client has ended it.
received = Hash.new { |all, id| all[id] = "".b }
echoed = "".b
50.times do
  exchange.call
  server.each_event do |event|
    next unless event.is_a?(QUIC::Event::StreamReadable)
    while (chunk = server.stream_read(event.stream_id, 65_536)) && !chunk.empty?
      received[event.stream_id] << chunk
    end
    server.stream_write(event.stream_id, received[event.stream_id], fin: true) if chunk.nil?
  end
  client.each_event { nil }
  while (chunk = client.stream_read(stream_id, 65_536)) && !chunk.empty?
    echoed << chunk
  end
  break if chunk.nil?
end

raise "Echo payload mismatch" unless echoed == payload

puts "Echo matched: #{echoed.bytesize} bytes"
