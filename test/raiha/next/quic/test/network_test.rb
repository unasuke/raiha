require "raiha/next/test_helper"
require "raiha/next/quic/test"

# 250 "Test API": nodes on a virtual clock, with path models between them.
class RaihaNextQUICTestNetworkTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
  Test = QUIC::Test

  A = ["192.0.2.1", 4433].freeze
  B = ["192.0.2.2", 443].freeze

  # Sends what it is told to at the times it is told, and keeps what it
  # receives with the time.
  class Node
    attr_reader :received

    def initialize(sends = {})
      @sends = sends.to_a
      @received = []
    end

    def receive(payload, from:, to:, ecn:, now:) = @received << [payload, from, to, ecn, now]

    def each_transmit(now:)
      while (time, transmit = @sends.first) && time <= now
        @sends.shift
        yield transmit
      end
    end

    def next_timeout = @sends.first&.first

    def handle_timeout(now:) = nil
  end

  # Sends back whatever it receives.
  class Echo < Node
    def receive(payload, from:, to:, ecn:, now:)
      super
      @sends << [now, QUIC::Transmit.new(payload:, destination: from, source: nil, ecn:, segment_size: nil)]
    end
  end

  # Holds each datagram `seconds`.
  class Delay < Data.define(:seconds)
    def start(random:) = State.new(seconds)

    class State
      def initialize(seconds)
        @seconds = seconds
        @queue = []
      end

      def submit(datagram, now:) = @queue << [now + @seconds, datagram]

      def each_delivery(now:)
        while (time, datagram = @queue.first) && time <= now
          @queue.shift
          yield datagram
        end
      end

      def next_timeout = @queue.first&.first
    end
  end

  def transmit(payload, to: B, ecn: :not_ect, segment_size: nil)
    QUIC::Transmit.new(payload:, destination: to, source: nil, ecn:, segment_size:)
  end

  def test_without_a_link_datagrams_arrive_at_once
    net = Test::Network.new(seed: 1)
    a = net.add(Node.new(0.0 => transmit("ping".b, ecn: :ect0)), address: A)
    b = net.add(Echo.new, address: B)
    assert net.run_until { a.received.any? }
    assert_equal [["ping", A, B, :ect0, 0.0]], b.received
    assert_equal [["ping", B, A, :ect0, 0.0]], a.received
  end

  # A model both ways, or one each way; an array of them in order.
  def test_links
    net = Test::Network.new(seed: 1)
    a = net.add(Node.new(0.0 => transmit("ping".b)), address: A)
    b = net.add(Echo.new, address: B)
    net.link(a, b, forward: Delay.new(0.1), reverse: [Delay.new(0.2), Delay.new(0.05)])
    assert net.run_until { a.received.any? }
    assert_in_delta 0.1, b.received.first.last
    assert_in_delta 0.35, a.received.first.last
    assert_in_delta 0.35, net.now
  end

  # Time goes on by the timers, and to the end however little happens.
  def test_advance
    net = Test::Network.new(seed: 1)
    net.add(Node.new(1.5 => transmit("late".b)), address: A)
    b = net.add(Node.new, address: B)
    net.advance(2.0)
    assert_equal [1.5], b.received.map(&:last)
    assert_equal 2.0, net.now
  end

  def test_run_until_gives_up
    net = Test::Network.new(seed: 1)
    net.add(Node.new(5.0 => transmit("late".b)), address: A)
    b = net.add(Node.new, address: B)
    refute net.run_until(within: 1.0) { b.received.any? }
    assert net.run_until { b.received.any? }
    refute net.run_until { false }
  end

  def test_segments_are_datagrams_of_their_own
    net = Test::Network.new(seed: 1)
    net.add(Node.new(0.0 => transmit("abcdefg".b, segment_size: 3)), address: A)
    b = net.add(Node.new, address: B)
    net.advance(0.0)
    assert_equal %w[abc def g], b.received.map(&:first)
  end

  def test_unknown_destinations_are_dropped
    net = Test::Network.new(seed: 1)
    net.add(Node.new(0.0 => transmit("lost".b, to: ["192.0.2.9", 1])), address: A)
    b = net.add(Node.new, address: B)
    net.advance(1.0)
    assert_empty b.received
  end

  # A timer that does nothing when run out keeps time from going on.
  def test_a_timer_left_in_the_past_is_stuck
    net = Test::Network.new(seed: 1)
    node = Node.new
    def node.next_timeout = 0.5
    net.add(node, address: A)
    assert_raises(Test::Network::Stuck) { net.advance(1.0) }
  end

  # Each direction gets its own randomness, the same for the same seed.
  def test_randomness_comes_from_the_seed
    draws = lambda do |seed|
      seen = []
      model = Object.new
      model.define_singleton_method(:start) do |random:|
        seen << random.rand
        Delay::State.new(0.0)
      end
      net = Test::Network.new(seed:)
      net.link(net.add(Node.new, address: A), net.add(Node.new, address: B), model:)
      seen
    end
    assert_equal draws.call(7), draws.call(7)
    refute_equal draws.call(7), draws.call(8)
    first, second = draws.call(7)
    refute_equal first, second
  end

  def test_virtual_clock
    clock = Test::VirtualClock.new(now: 1.0)
    clock.advance(0.5)
    assert_equal 1.5, clock.now
    assert_raises(ArgumentError) { clock.advance_to(1.0) }
  end
end
