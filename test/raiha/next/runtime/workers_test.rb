require "raiha/next/test_helper"
require "raiha/next/runtime"
require "raiha/next/support/runtime_owner"
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

  def test_the_arguments
    assert_raises(ArgumentError) { workers(count: 0) { nil } }
    assert_raises(ArgumentError) { workers(count: Runtime::Workers::MAX + 1) { nil } }
    assert_raises(ArgumentError) { workers(config: QUIC::Config.new(connection_id_length: 3)) { nil } }
    assert_raises(ArgumentError) { workers }
  end
end
