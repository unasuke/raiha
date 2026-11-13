require "test_helper"
require "raiha/runtime"
require "support/runtime_owner"
require "async"

# The workers of a server, each in a Ractor of its own: what each is given,
# that the end of one ends them all, and that what one raises comes out of
# `run`.
class RaihaNextRuntimeWorkersTest < Minitest::Test
  include NextRuntimeOwner

  def workers(count: 2, config: QUIC::Config.new, args: [], &) = Runtime::Workers.new(count:, config:, host: "127.0.0.1", port: 0, args:, &)

  # Each worker is given its ID, the count, sockets on one port, and the
  # Config with the keys it left out, the same for all; `run` returns once
  # their blocks are over.
  def test_what_each_worker_is_given
    seen = Ractor::Port.new
    workers = workers(args: [seen]) do |worker, seen|
      socket = worker.sockets.first
      seen.send([worker.id, worker.count, worker.sockets.size, socket.local_address.ip_port, worker.config.stateless_reset_key,
        worker.config.retry_token_key, Ractor.shareable?(worker.anti_replay)])
    end
    assert_nil workers.run
    got = Array.new(2) { seen.receive }.sort_by(&:first)
    port = workers.local_address.fetch(1)
    assert_equal [[0, 2, 1, port], [1, 2, 1, port]], got.map { |values| values.first(4) }
    assert_equal 1, got.map { |values| values[4..5] }.uniq.size
    assert got.all? { |values| values[4].bytesize >= QUIC::Config::MIN_KEY_LENGTH && values[6] }
  end

  # The keys a Config has are kept.
  def test_keys_given_are_kept
    seen = Ractor::Port.new
    config = QUIC::Config.new(stateless_reset_key: "k".b * 32, retry_token_key: "r".b * 32)
    workers(count: 1, config:, args: [seen]) { |worker, seen| seen.send(worker.config.stateless_reset_key) }.run
    assert_equal "k".b * 32, seen.receive
  end

  # A preferred address the first socket does not take has a socket of its
  # own in each worker.
  def test_a_socket_for_a_preferred_address
    seen = Ractor::Port.new
    preferred = { ipv4: ["127.0.0.1", free_port] }
    workers(config: QUIC::Config.new(preferred_address: preferred), args: [seen]) do |worker, seen|
      seen.send(worker.sockets.map { |socket| socket.local_address.ip_port })
    end.run
    ports = Array.new(2) { seen.receive }
    assert ports.all? { |main, other| other == preferred[:ipv4][1] && main != other }
  end

  # One worker raising has the others, servers here, told to stop, and
  # `run` raises it.
  def test_what_a_worker_raises
    tls = server_config
    workers = workers(args: [tls, Ractor.make_shareable(NextTLSPair.server_identity)]) do |worker, tls, identity|
      raise "worker 0 failed" if worker.id.zero?
      keyring = Raiha::Next::TLS::Keyring.server(config: tls, identities: [identity])
      Sync { Raiha::Next::Runtime::Server.new(config: worker.config, tls_config: tls, keyring:, worker:).run { nil } }
    end
    error = assert_raises(RuntimeError) { workers.run }
    assert_equal "worker 0 failed", error.message
  end

  # Workers serving echo, each answering with its ID, run in a thread of
  # their own: the workers and the thread, once they bound their sockets.
  def serving(count: 2)
    tls = server_config
    workers = workers(count:, args: [tls, Ractor.make_shareable(NextTLSPair.server_identity)]) do |worker, tls, identity|
      keyring = Raiha::Next::TLS::Keyring.server(config: tls, identities: [identity])
      Sync do
        Raiha::Next::Runtime::Server.new(config: worker.config, tls_config: tls, keyring:, worker:).run do |session|
          session.each_stream { |stream| (stream << "ECHO#{worker.id}:" << stream.read).close_write }
        end
      end
    end
    running = Thread.new { workers.run }
    sleep 0.01 until workers.local_address || !running.alive?
    [workers, running]
  end

  # What a stream to the workers at `port` is answered.
  def echo(port, data, server_name: "localhost")
    tls = client_config
    Sync do
      Runtime::Client.connect("127.0.0.1", port, config: QUIC::Config.new, tls_config: tls, keyring: client_keyring(config: tls), server_name:) do |session|
        stream = session.open_stream
        stream << data
        stream.close_write
        stream.read
      end
    end
  end

  # A stop asked from a signal handler has every worker stop, and `run`
  # return.
  def test_a_stop_from_a_signal_handler
    workers, running = serving
    assert_match(/\AECHO[01]:hi\z/, echo(workers.local_address.fetch(1), "hi"))
    previous = Signal.trap(:USR2) { workers.stop(timeout: 1) }
    Process.kill(:USR2, Process.pid)
    assert running.join(10), "the workers did not stop"
    assert_nil running.value
  ensure
    Signal.trap(:USR2, previous || "DEFAULT")
  end

  # A stop asked before the workers run has them stop once they do.
  def test_a_stop_before_they_run
    workers, running = serving.tap { |workers, _| workers.stop(timeout: 1) }
    assert running.join(10), "the workers did not stop"
  ensure
    workers&.stop
  end

  # Each worker answers what it counted; one whose server is not running
  # does not, and is nil.
  def test_stats
    workers, running = serving
    stats = workers.stats
    assert_equal [0, 1], stats.map(&:id)
    assert stats.all? { |stat| [stat.sent, stat.received, stat.dropped] == [0, 0, 0] }
    workers.stop(timeout: 1)
    running.join(10)
    quiet = workers(count: 4) { sleep 0.5 }
    still = Thread.new { quiet.run }
    sleep 0.01 until quiet.local_address
    sleep 0.05
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert_equal [nil] * 4, quiet.stats(timeout: 0.1)
    # They are asked at once, not one after another.
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.3
    still.join(10)
  ensure
    workers&.stop
  end

  # Other TLS settings and identities are taken for the connections to
  # come: a certificate for another name has a client of "localhost" fail.
  def test_reconfigure
    workers, running = serving
    port = workers.local_address.fetch(1)
    assert_match(/\AECHO[01]:before\z/, echo(port, "before"))
    other = Ractor.make_shareable(NextTLSPair.server_identity(names: ["DNS:other.example"]))
    workers.reconfigure(tls_config: server_config, identities: [other])
    sleep 0.1
    assert_match(/\AECHO[01]:other\z/, echo(port, "other", server_name: "other.example"))
    error = assert_raises(Runtime::ConnectError) { echo(port, "localhost") }
    assert_match(/certificate_rejected/, error.message)
  ensure
    workers&.stop(timeout: 1)
    running&.join(10)
  end

  def test_the_arguments
    assert_raises(ArgumentError) { workers(count: 0) { nil } }
    assert_raises(ArgumentError) { workers(count: Runtime::Workers::MAX + 1) { nil } }
    assert_raises(ArgumentError) { workers(config: QUIC::Config.new(connection_id_length: 3)) { nil } }
    assert_raises(ArgumentError) { workers }
  end
end
