#!/usr/bin/env ruby
# frozen_string_literal: true

# Allocations of the next release of raiha's QUIC, to see regressions by
# hand: a handshake, a client and a server Connection passing datagrams to
# each other in memory, and a transfer of TRANSFER bytes between them, a
# packet of which goes through streams, packet protection, loss recovery
# and pacing, counted over the packets either end sends. A millisecond
# goes by each round trip. Allocations vary by a few from run to run, with
# the random bytes the handshakes draw; time is for reference.
#
# Usage: bundle exec ruby [--yjit] script/allocation_bench.rb

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "raiha/quic"
require_relative "../../examples/_certificate"

QUIC = Raiha::QUIC
TLS = Raiha::TLS
REGISTRY = TLS::Extension::Registry::BUILTIN.with(QUIC::TransportParameters::Extension)
ALPN = ["hq-interop"].freeze
HANDSHAKES = 50
# YJIT compiles a method once it has been called 30 times, by default.
WARM_UP = 30
TRANSFER = 20_000_000
CLIENT = ["192.0.2.1", 50_000].freeze
SERVER = ["192.0.2.2", 443].freeze

SERVER_TLS = TLS::Config.server(profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY)
SERVER_KEYRING = TLS::Keyring.server(config: SERVER_TLS, identities: [ExampleCertificate.identity])
CLIENT_TLS = TLS::Config.client(trust_anchors: [ExampleCertificate.ca_der], profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY)
CLIENT_KEYRING = TLS::Keyring.client(config: CLIENT_TLS)

# The certificate is made now, so the connections' clock starts now.
def pair
  time = Time.now
  client = QUIC::Connection.client(config: QUIC::Config.new, tls_config: CLIENT_TLS, keyring: CLIENT_KEYRING, server_name: "localhost",
    remote: SERVER, time:, now: 0.0)
  server = QUIC::Connection.server(config: QUIC::Config.new, tls_config: SERVER_TLS, keyring: SERVER_KEYRING, time:, now: 0.0)
  [client, server]
end

# One round trip: what each sends goes to the other, the server's after
# half of it; the time after it.
def round(client, server, now)
  client.each_transmit(now:) { |transmit| server.receive(transmit.payload, from: CLIENT, now:) }
  now += 0.0005
  server.each_transmit(now:) { |transmit| client.receive(transmit.payload, from: SERVER, now:) }
  now += 0.0005
  [client, server].each do |connection|
    deadline = connection.next_timeout
    connection.handle_timeout(now:) if deadline && deadline <= now
    connection.each_event { nil }
    raise "closed: #{connection.close_reason.inspect}" if connection.close_reason
  end
  now
end

def handshake
  client, server = pair
  now = 0.0
  now = round(client, server, now) until client.handshake_confirmed? && server.handshake_confirmed?
  [client, server, now]
end

def transfer
  client, server, now = handshake
  stream = client.open_stream
  client.stream_write(stream, "GET", fin: true)
  now = round(client, server, now) until server.readable_streams.include?(stream)
  server.stream_read(stream, 100)
  piece = "x".b * 65_536
  written = 0
  read = 0
  while read < TRANSFER
    while written < TRANSFER
      taken = server.stream_write(stream, written + piece.bytesize > TRANSFER ? piece.byteslice(0, TRANSFER - written) : piece,
        fin: written + piece.bytesize >= TRANSFER)
      break if taken.zero?
      written += taken
    end
    now = round(client, server, now)
    while (data = client.stream_read(stream, 1 << 20)) && !data.empty?
      read += data.bytesize
    end
  end
  client.stats.packets_sent + server.stats.packets_sent
end

def measure(name, per)
  GC.start
  allocated = GC.stat(:total_allocated_objects)
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  count = yield
  elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
  objects = GC.stat(:total_allocated_objects) - allocated
  puts format("%-10s %10.1f allocations/%s %10.1f µs/%s  (%d %ss)", name, objects.fdiv(count), per, elapsed * 1_000_000 / count, per, count, per)
end

puts RUBY_DESCRIPTION
# Warm up the code paths, so that neither loading nor YJIT's compiling of
# the handshake counts.
WARM_UP.times { handshake }
measure("handshake", "connection") do
  HANDSHAKES.times { handshake }
  HANDSHAKES
end
measure("transfer", "packet") { transfer }
