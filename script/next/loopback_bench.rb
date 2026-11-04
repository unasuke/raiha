#!/usr/bin/env ruby
# frozen_string_literal: true

# The runtime of the next release of raiha on the loopback interface, to
# see regressions by hand: the throughput of one connection the server
# sends MEGABYTES on, and the handshakes a second one server takes, a
# client connecting again and again for SECONDS. The server runs in a
# process of its own and the client in this one, each in the scheduler of
# the async gem. Times depend on the machine: compare runs on the same
# one.
#
# Usage:
#   bundle exec ruby script/next/loopback_bench.rb throughput [MEGABYTES]   (50 by default)
#   bundle exec ruby script/next/loopback_bench.rb handshakes [SECONDS]     (10 by default)
#   bundle exec ruby --yjit script/next/loopback_bench.rb ...                (YJIT in both)

$LOAD_PATH.unshift(File.expand_path("../../lib", __dir__))

require "raiha/next/runtime"
# The scheduler of async reads with IO::Buffer, which Ruby 4.0 warns is
# experimental.
Warning[:experimental] = false
require "async"
require_relative "../../examples/next/_certificate"

Runtime = Raiha::Next::Runtime
QUIC = Raiha::Next::QUIC
TLS = Raiha::Next::TLS
REGISTRY = TLS::Extension::Registry::BUILTIN.with(QUIC::TransportParameters::Extension)
ALPN = ["hq-interop"].freeze
PIECE = 65_536

mode = ARGV.fetch(0) { abort "usage: loopback_bench.rb throughput [MEGABYTES] | handshakes [SECONDS]" }
amount = Float(ARGV.fetch(1, mode == "throughput" ? "50" : "10"))
identity = ExampleCertificate.identity
ca = ExampleCertificate.ca_der

# The server in a child process: on each stream, the number of bytes the
# client asks for, sent back. Its port comes back on the pipe.
reader, writer = IO.pipe
server_pid = fork do
  reader.close
  tls = TLS::Config.server(profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY)
  server = Runtime::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: TLS::Keyring.server(config: tls, identities: [identity]),
    host: "127.0.0.1", port: 0)
  Signal.trap("TERM") { server.stop(timeout: 1) }
  Async do
    running = Async do
      server.run do |session|
        session.each_stream do |stream|
          left = Integer(stream.read)
          piece = "x".b * PIECE
          while left.positive?
            stream << (left >= PIECE ? piece : piece.byteslice(0, left))
            left -= PIECE
          end
          stream.close_write
        end
      end
    end
    sleep 0.01 until server.local_address
    writer.puts(server.local_address[1])
    writer.close
    running.wait
  end
end
writer.close
port = Integer(reader.gets)
tls = TLS::Config.client(trust_anchors: [ca], profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY)
clock = -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
connect = lambda do |&block|
  Runtime::Client.connect("127.0.0.1", port, server_name: "localhost", config: QUIC::Config.new, tls_config: tls,
    keyring: TLS::Keyring.client(config: tls), &block)
end

begin
  Async do
    case mode
    when "throughput"
      size = (amount * 1_000_000).to_i
      connect.call do |session|
        stream = session.open_stream
        stream << size.to_s
        stream.close_write
        started = clock.call
        received = 0
        while (chunk = stream.read(PIECE))
          received += chunk.bytesize
        end
        elapsed = clock.call - started
        raise "received #{received} of #{size}" unless received == size
        puts format("%s: %d MB in %.2f s, %.1f Mbit/s", RUBY_DESCRIPTION, size / 1_000_000, elapsed, received * 8 / elapsed / 1_000_000)
      end
    when "handshakes"
      count = 0
      started = clock.call
      until clock.call - started >= amount
        connect.call { |session| session.wait_handshake }
        count += 1
      end
      elapsed = clock.call - started
      puts format("%s: %d handshakes in %.2f s, %.1f a second", RUBY_DESCRIPTION, count, elapsed, count / elapsed)
    else abort "unknown mode #{mode}"
    end
  end
ensure
  Process.kill("TERM", server_pid)
  Process.wait(server_pid)
end
