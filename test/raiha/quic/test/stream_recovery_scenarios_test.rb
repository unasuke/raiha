require "test_helper"
require "support/quic_transfer"
require "support/quic_recovery"

# Loss recovery in transfers on a Test::Network, on virtual time: the
# scenarios that need streams.
class RaihaNextQUICTestStreamRecoveryScenariosTest < Minitest::Test
  include NextQUICTransfer

  RecordingTracer = NextQUICRecovery::RecordingTracer

  # 10 Mbps and 20 ms each way, with a queue that never fills.
  DEEP = Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.02, queue: 100_000_000)

  # A path model that, from the datagram at place `from`, counted from 0
  # as they enter, drops every other one, `count` of them.
  class EveryOther < Data.define(:from, :count)
    def start(random:) = State.new(from, count)

    class State
      def initialize(from, count)
        @dropped = (from...from + 2 * count).step(2).to_a
        @place = -1
        @queue = []
      end

      def submit(datagram, now:)
        @place += 1
        @queue << datagram unless @dropped.include?(@place)
      end

      def each_delivery(now:)
        queue = @queue
        @queue = []
        queue.each { yield _1 }
      end

      def next_timeout = nil
    end
  end

  # 1 MB with nothing lost, with 2 % lost, and reordered by one place or
  # by up to four: each transfer ends. One place is within the packet
  # threshold and nothing looks lost; past it, every loss declared turns out
  # spurious.
  def test_lost_and_reordered
    {
      clean: [DEEP, 0, 0],
      lossy: [[Test::RandomLoss.new(rate: 0.02), DEEP], 1.., 0],
      reordered: [[Test::Reorder.new(rate: 0.1), DEEP], 0, 0],
      further: [Array.new(4) { Test::Reorder.new(rate: 0.1) } + [DEEP], 1.., :lost],
    }.each do |name, (model, lost, spurious)|
      net, _, server, reads = download(1_000_000, model:)
      assert net.run_until(within: 30.0) { reads.last&.last == 1_000_000 }, name
      stats = server.connections.first.stats
      assert_operator lost, :===, stats.packets_lost, name
      assert_equal spurious == :lost ? stats.packets_lost : spurious, stats.packets_spuriously_lost, name
    end
  end

  # Every other datagram to the client lost, 150 of them: the client's
  # ACKs carry no more than 64 ranges and the connection stays. Sending only
  # ACKs, the client adds a PING to one once a round trip, never to two in
  # a row.
  def test_many_holes_at_the_receiver
    tracer = RecordingTracer.new
    path = Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.02, queue: 300_000)
    net, client, server, reads = download(2_000_000, forward: path, reverse: [EveryOther.new(from: 200, count: 150), path],
      client_tracer: tracer)
    assert net.run_until(within: 30.0) { reads.last&.last == 2_000_000 }
    assert_nil client.close_reason
    assert_operator server.connections.first.stats.packets_lost, :>=, 150
    sent = tracer.of(:packet_sent).select { _1[:header].packet_type == :one_rtt }
    acks = sent.flat_map { |packet| packet[:frames].grep(QUIC::Wire::Frame::Ack) }
    assert_equal QUIC::Recovery::MAX_ACK_RANGES, acks.map { _1.ranges.size }.max
    alone = sent.select { |packet| packet[:frames].all? { _1.is_a?(QUIC::Wire::Frame::Ack) || _1.is_a?(QUIC::Wire::Frame::Ping) } }
    ping = ->(packet) { packet[:frames].last.is_a?(QUIC::Wire::Frame::Ping) }
    pings = alone.select(&ping)
    assert_operator pings.size, :>, 5
    assert pings.each_cons(2).all? { |a, b| b[:now] - a[:now] >= client.stats.min_rtt }
    refute alone.each_cons(2).any? { |a, b| ping.(a) && ping.(b) }
  end
end
