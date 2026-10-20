require "raiha/next/test_helper"
require "raiha/next/quic/test"
require "raiha/next/support/quic_pair"
require "raiha/next/support/quic_recovery"

# Loss recovery in handshakes on a Test::Network, on virtual time: the
# scenarios that need no streams.
class RaihaNextQUICTestRecoveryScenariosTest < Minitest::Test
  include NextQUICPair

  Test = QUIC::Test
  RecordingTracer = NextQUICRecovery::RecordingTracer

  # A path model that drops the datagrams whose places, counted from 0 as
  # they enter, are in `drop`.
  class DropNth < Data.define(:drop)
    def start(random:) = State.new(drop)

    class State
      def initialize(drop)
        @drop = drop
        @count = -1
        @queue = []
      end

      def submit(datagram, now:)
        @count += 1
        @queue << datagram unless @drop.include?(@count)
      end

      def each_delivery(now:)
        queue = @queue
        @queue = []
        queue.each { yield _1 }
      end

      def next_timeout = nil
    end
  end

  # A path model that drops what enters from `from` until `to`.
  class Blackout < Data.define(:from, :to)
    def start(random:) = State.new(from...to)

    class State
      def initialize(span)
        @span = span
        @queue = []
      end

      def submit(datagram, now:) = (@queue << datagram unless @span.cover?(now))

      def each_delivery(now:)
        queue = @queue
        @queue = []
        queue.each { yield _1 }
      end

      def next_timeout = nil
    end
  end

  DELAY = Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.01, queue: 100_000)

  def network(forward:, reverse:, client_tracer: nil, **server)
    net = Test::Network.new(seed: 1)
    client = net.add(client_connection(tracer: client_tracer), address: CLIENT)
    tls_config = server_config
    keyring = TLS::Keyring.server(config: tls_config, identities: [NextTLSPair.server_identity], random: Random.new(2))
    host = net.add_server(config: QUIC::Config.new, tls_config:, keyring:, time: NOW, address: SERVER, **server)
    net.link(client, host, forward:, reverse:)
    [net, client, host]
  end

  def handshaken?(client, host) = client.handshake_confirmed? && host.connections.any?(&:handshake_confirmed?)

  # The metrics as they stood after each `metrics_updated`.
  def metrics(tracer) = tracer.of(:metrics_updated).each_with_object([]) { |event, all| all << (all.last || {}).merge(event) }

  # The client's datagram with its Finished is lost: its PTO sends two
  # probes, which complete the handshake.
  def test_the_last_datagram_lost
    tracer = RecordingTracer.new
    net, client, host = network(forward: [DropNth.new(drop: [1]), DELAY], reverse: DELAY, client_tracer: tracer)
    assert net.run_until { handshaken?(client, host) }
    expired = tracer.of(:timer_updated).find { _1[:timer_type] == :loss_timeout && _1[:event_type] == :expired }
    probes = tracer.of(:packet_sent).select { _1[:now] == expired[:now] }
    assert_equal [:handshake, :handshake], probes.map { _1[:header].packet_type }
  end

  # A server that never answers: the PTO doubles each time, and the idle
  # timeout closes the connection.
  def test_a_server_that_never_answers
    tracer = RecordingTracer.new
    net, client, = network(forward: DELAY, reverse: Test::RandomLoss.new(rate: 1.0), client_tracer: tracer)
    assert net.run_until(within: 40.0) { client.closed? }
    assert_equal "idle timeout", client.close_reason.reason
    assert_in_delta QUIC::Config.new.max_idle_timeout, net.now, 1.0
    times = tracer.of(:packet_sent).map { _1[:now] }.uniq
    assert_operator times.size, :>=, 4
    times.each_cons(3) { |a, b, c| assert_in_delta 2.0, (c - b) / (b - a), 0.01, times.inspect }
  end

  # Nothing the server sends gets through for two seconds once it has
  # completed the handshake, with an RTT sample: its HANDSHAKE_DONE and
  # the probes after it are lost, and when the ACK of one comes, the losses
  # make persistent congestion, which takes its window to the minimum, to
  # grow by what the ACK acknowledged. That min_rtt is taken again with it,
  # the unit tests of Recovery show.
  def test_a_long_blackout
    tracer = RecordingTracer.new
    net, client, host = network(forward: DELAY, reverse: [Blackout.new(from: 0.025, to: 2.0), DELAY], tracer:)
    assert net.run_until { handshaken?(client, host) }
    assert_operator net.now, :>=, 2.0
    net.advance(1.0)
    windows = metrics(tracer).map { _1[:congestion_window] }
    minimum = 2 * QUIC::Config.new.initial_max_datagram_size
    assert windows.any? { (minimum...2 * minimum).cover?(_1) }, windows.inspect
  end

  # RFC 9002 "Handling Retry": a Retry before any PTO gives an RTT sample
  # of the time from the first Initial, 5 ms at least.
  def test_an_rtt_sample_from_a_retry
    tracer = RecordingTracer.new
    path = Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.001, queue: 100_000)
    net, client, host = network(forward: path, reverse: path, client_tracer: tracer, retry_unvalidated: true)
    assert net.run_until { handshaken?(client, host) }
    assert_equal QUIC::Recovery::MIN_RETRY_RTT, metrics(tracer).find { _1[:latest_rtt] }[:latest_rtt]
  end
end
