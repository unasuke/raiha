#!/usr/bin/env ruby
# frozen_string_literal: true

# The runtime of the next release of raiha on the loopback interface, to
# see regressions by hand: the throughput of one connection the server
# sends MEGABYTES on, and the handshakes a second one server takes, a
# client connecting again and again for SECONDS. The server runs in a
# process of its own and the clients in others, each in the scheduler of
# the async gem. Times depend on the machine: compare runs on the same
# one.
#
# With `--workers N` the server is N workers (Runtime::Workers), and with
# `--clients M` M client processes run at once, whose results add up.
# `forwarded` measures one connection to two workers or more whose client
# keeps moving to another port until what it sends is handed on from the
# worker it lands on to the worker of the connection, against the same
# client that does not move; that client is a bare Connection, run here.
#
# Usage:
#   bundle exec ruby script/next/loopback_bench.rb throughput [MEGABYTES] [--workers N] [--clients M]   (50 by default)
#   bundle exec ruby script/next/loopback_bench.rb handshakes [SECONDS] [--workers N] [--clients M]     (10 by default)
#   bundle exec ruby script/next/loopback_bench.rb forwarded [MEGABYTES] --workers N                   (N 2 at least)
#   bundle exec ruby --yjit script/next/loopback_bench.rb ...                                           (YJIT in all)

$LOAD_PATH.unshift(File.expand_path("../../lib", __dir__))

require "optparse"
require "securerandom"
require "raiha/next/runtime"
# The scheduler of async reads with IO::Buffer, which Ruby 4.0 warns is
# experimental, and the workers are Ractors.
Warning[:experimental] = false
require "async"
require_relative "../../examples/next/_certificate"

Runtime = Raiha::Next::Runtime
QUIC = Raiha::Next::QUIC
TLS = Raiha::Next::TLS
REGISTRY = TLS::Extension::Registry::BUILTIN.with(QUIC::TransportParameters::Extension)
ALPN = ["hq-interop"].freeze
PIECE = 65_536
# How many times the client of `forwarded` moves at most to land on a
# worker that hands it on.
MOVES = 32

# What the server does with each session: on each stream, the number of
# bytes the client asks for, sent back.
SERVE = Ractor.shareable_lambda do |session|
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

workers = 0
clients = 1
mode, amount = OptionParser.new do |options|
  options.on("--workers N", Integer) { |n| workers = n }
  options.on("--clients M", Integer) { |n| clients = n }
end.parse(ARGV)
abort "usage: loopback_bench.rb throughput [MEGABYTES] | handshakes [SECONDS] | forwarded [MEGABYTES] [--workers N] [--clients M]" unless mode
abort "forwarded needs --workers 2 at least" if mode == "forwarded" && workers < 2
amount = Float(amount || (mode == "handshakes" ? "10" : "50"))
identity = Ractor.make_shareable(ExampleCertificate.identity)
ca = ExampleCertificate.ca_der
server_tls = TLS::Config.server(profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY)

# The server in a child process, of `workers` workers or one Runtime::Server;
# its port comes back on `ready`. A line on `asked` has it put the
# datagrams its workers handed on so far on `told`.
ready, ready_writer = IO.pipe
asked, asking = IO.pipe
telling, told = IO.pipe
server_pid = fork do
  [ready, asking, telling].each(&:close)
  if workers.zero?
    server = Runtime::Server.new(config: QUIC::Config.new, tls_config: server_tls,
      keyring: TLS::Keyring.server(config: server_tls, identities: [identity]), host: "127.0.0.1", port: 0)
    Signal.trap("TERM") { server.stop(timeout: 1) }
    Async do
      running = Async { server.run(&SERVE) }
      sleep 0.01 until server.local_address
      ready_writer.puts(server.local_address[1])
      ready_writer.close
      running.wait
    end
  else
    pool = Runtime::Workers.new(count: workers, config: QUIC::Config.new, host: "127.0.0.1", port: 0,
      args: [server_tls, identity, SERVE]) do |worker, tls, identity, serve|
      keyring = TLS::Keyring.server(config: tls, identities: [identity])
      Async { Runtime::Server.new(config: worker.config, tls_config: tls, keyring:, worker:).run(&serve) }
    end
    Signal.trap("TERM") { pool.stop(timeout: 1) }
    Thread.new do
      sleep 0.01 until pool.local_address
      ready_writer.puts(pool.local_address[1])
      ready_writer.close
      while asked.gets
        told.puts(pool.stats.sum { |stats| stats&.sent || 0 })
      end
    end
    pool.run
  end
end
[ready_writer, asked, told].each(&:close)
port = Integer(ready.gets)
client_tls = TLS::Config.client(trust_anchors: [ca], profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY)
clock = -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
connect = lambda do |&block|
  Runtime::Client.connect("127.0.0.1", port, server_name: "localhost", config: QUIC::Config.new, tls_config: client_tls,
    keyring: TLS::Keyring.client(config: client_tls), &block)
end

# What one client measures: [bytes, seconds] of a throughput, or
# [handshakes, seconds].
measure = lambda do
  result = nil
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
        raise "received #{received} of #{size}" unless received == size
        result = [received, clock.call - started]
      end
    when "handshakes"
      count = 0
      started = clock.call
      until clock.call - started >= amount
        connect.call { |session| session.wait_handshake }
        count += 1
      end
      result = [count, clock.call - started]
    else abort "unknown mode #{mode}"
    end
  end
  result
end

# A bare client Connection on a socket of its own, which `move!` moves to
# another, run with a loop of its own: the throughput of a stream of
# `size` bytes as [bytes, seconds].
class Mover
  ISSUER = QUIC::Endpoint::Issuer.new(->(_connection) { [SecureRandom.bytes(8), SecureRandom.bytes(16)] }, ->(_connection_id) {})

  def initialize(port, tls)
    @socket = bound
    @connection = QUIC::Connection.client(config: QUIC::Config.new, tls_config: tls, keyring: TLS::Keyring.client(config: tls),
      server_name: "localhost", remote: ["127.0.0.1", port], time: Time.now, now: clock, issuer: ISSUER)
    drive { @connection.handshake_confirmed? }
  end

  def clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)

  def bound = UDPSocket.new.tap { |socket| socket.bind("127.0.0.1", 0) }

  def move!
    @socket.close
    @socket = bound
  end

  # A stream that asks for nothing, and a little time for it to go and be
  # answered.
  def poke
    @connection.stream_write(@connection.open_stream || raise("no stream left"), "0", fin: true)
    drive(seconds: 0.1) { false }
  end

  def throughput(size)
    stream_id = @connection.open_stream
    @connection.stream_write(stream_id, size.to_s, fin: true)
    started = clock
    received = 0
    drive(seconds: 600) do
      while (chunk = @connection.stream_read(stream_id, PIECE))
        break if chunk.empty?
        received += chunk.bytesize
      end
      chunk.nil?
    end or raise "the stream did not end"
    raise "received #{received} of #{size}" unless received == size
    [received, clock - started]
  end

  def close
    @connection.close(now: clock)
    @connection.each_transmit(now: clock) { |transmit| @socket.send(transmit.payload, 0, *transmit.destination) }
    @socket.close
  end

  # Runs the connection until the block is true or `seconds` have gone by:
  # whether the block came true. Its events are let go, as the connection
  # closes once too many wait.
  private def drive(seconds: 10)
    limit = clock + seconds
    until yield
      return false if clock > limit
      @connection.each_event { nil }
      @connection.each_transmit(now: clock) { |transmit| @socket.send(transmit.payload, 0, *transmit.destination) }
      deadline = [@connection.next_timeout, limit].compact.min
      if IO.select([@socket], nil, nil, [deadline - clock, 0].max)
        data, from = @socket.recvfrom(65_535)
        @connection.receive(data, from: [from[3], from[1]], to: nil, ecn: :not_ect, now: clock)
      else
        @connection.handle_timeout(now: clock)
      end
    end
    true
  end
end

forwarded_so_far = lambda do
  asking.puts
  Integer(telling.gets)
end

begin
  case mode
  when "forwarded"
    size = (amount * 1_000_000).to_i
    still = Mover.new(port, client_tls)
    bytes, seconds = still.throughput(size)
    still.close
    puts format("%s: %d workers, not moving: %.1f Mbit/s", RUBY_DESCRIPTION, workers, bytes * 8 / seconds / 1_000_000)
    mover = Mover.new(port, client_tls)
    before = forwarded_so_far.call
    moves = 0
    until moves == MOVES
      mover.move!
      moves += 1
      mover.poke
      break if forwarded_so_far.call > before
    end
    abort "nothing was handed on in #{MOVES} moves" if moves == MOVES
    before = forwarded_so_far.call
    bytes, seconds = mover.throughput(size)
    handed_on = forwarded_so_far.call - before
    mover.close
    puts format("%s: %d workers, handed on after %d moves: %.1f Mbit/s, %d datagrams handed on", RUBY_DESCRIPTION, workers, moves,
      bytes * 8 / seconds / 1_000_000, handed_on)
  else
    # Each client in a process of its own, its result on a pipe.
    results = Array.new(clients) do
      reader, writer = IO.pipe
      pid = fork do
        reader.close
        writer.puts(measure.call.join(" "))
      end
      writer.close
      [pid, reader]
    end.map do |pid, reader|
      line = reader.gets or abort "a client failed"
      Process.wait(pid)
      line.split.map { |value| Float(value) }
    end
    total = results.sum(&:first)
    seconds = results.map(&:last).max
    if mode == "throughput"
      puts format("%s: %d workers, %d clients: %d MB in %.2f s, %.1f Mbit/s", RUBY_DESCRIPTION, workers, clients, total / 1_000_000,
        seconds, total * 8 / seconds / 1_000_000)
    else
      puts format("%s: %d workers, %d clients: %d handshakes in %.2f s, %.1f a second", RUBY_DESCRIPTION, workers, clients, total, seconds,
        total / seconds)
    end
  end
ensure
  Process.kill("TERM", server_pid)
  Process.wait(server_pid)
end
