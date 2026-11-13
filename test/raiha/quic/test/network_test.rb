require "test_helper"
require "raiha/quic/test"

# Nodes on a virtual clock, with path models between them.
class RaihaQUICTestNetworkTest < Minitest::Test
  QUIC = Raiha::QUIC
  Test = QUIC::Test

  A = ["192.0.2.1", 4433].freeze
  B = ["192.0.2.2", 443].freeze

  # A node whose first timer, run out, sets another that is due at once,
  # with nothing sent.
  class Chained
    attr_reader :handled

    def initialize
      @timeouts = [1.0, 0.5]
      @handled = []
    end

    def receive(*, **) = nil

    def each_transmit(now:) = nil

    def next_timeout = @timeouts.first

    def handle_timeout(now:) = @handled << [@timeouts.shift, now]
  end

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

    # Sends `transmit` at `time`, after what it sends before then.
    def push(time, transmit) = @sends << [time, transmit]
  end

  # Sends back whatever it receives.
  class Echo < Node
    def receive(payload, from:, to:, ecn:, now:)
      super
      push(now, QUIC::Transmit.new(payload:, destination: from, source: nil, ecn:, segment_size: nil))
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

  # Behind a NAT, what a node sends leaves from the NAT's address, and what
  # comes back to that address reaches the node at its own. Once the NAT
  # binds another, what comes to the address before is lost, as is what
  # comes to the node's own address.
  def test_a_nat
    net = Test::Network.new(seed: 1)
    a = net.add(Node.new(0.0 => transmit("one".b), 1.0 => transmit("two".b)), address: A)
    b = net.add(Echo.new, address: B)
    net.rebind(A, to: ["203.0.113.1", 50_000])
    net.advance(0.5)
    assert_equal [["one", ["203.0.113.1", 50_000], B]], b.received.map { _1.take(3) }
    assert_equal [["one", B, A]], a.received.map { _1.take(3) }
    net.rebind(A, to: ["203.0.113.2", 50_001])
    b.received.clear
    b.push(1.0, transmit("old".b, to: ["203.0.113.1", 50_000]))
    b.push(1.0, transmit("own".b, to: A))
    net.advance(1.0)
    assert_equal [["two", ["203.0.113.2", 50_001], B]], b.received.map { _1.take(3) }
    assert_equal %w[one two], a.received.map(&:first)
  end

  # A node with a second address takes what comes to it, and sends from
  # it when a Transmit names it as the source; it cannot send from an
  # address that is not its own.
  def test_a_second_address
    net = Test::Network.new(seed: 1)
    a = net.add(Node.new(0.0 => transmit("ping".b, to: ["192.0.2.3", 443])), address: A)
    b = net.add(Node.new, address: B)
    net.add_address(b, address: ["192.0.2.3", 443])
    net.advance(0.0)
    assert_equal [["ping", A, ["192.0.2.3", 443]]], b.received.map { _1.take(3) }
    b.push(0.0, QUIC::Transmit.new(payload: "pong".b, destination: A, source: ["192.0.2.3", 443], ecn: :not_ect, segment_size: nil))
    net.advance(0.0)
    assert_equal [["pong", ["192.0.2.3", 443], A]], a.received.map { _1.take(3) }
    assert_raises(ArgumentError) { net.add_address(a, address: B) }
    b.push(0.0, QUIC::Transmit.new(payload: "x".b, destination: A, source: A, ecn: :not_ect, segment_size: nil))
    assert_raises(ArgumentError) { net.advance(0.0) }
  end

  # The link between two nodes carries what goes between them, whichever
  # of their addresses, or the NAT's, it goes from and to.
  def test_a_link_between_nodes_whatever_their_addresses
    net = Test::Network.new(seed: 1)
    a = net.add(Node.new(0.0 => transmit("first".b, to: ["192.0.2.3", 443])), address: A)
    b = net.add(Echo.new, address: B)
    net.add_address(b, address: ["192.0.2.3", 443])
    net.rebind(A, to: ["203.0.113.1", 50_000])
    net.link(a, b, model: Delay.new(0.1))
    assert net.run_until { a.received.any? }
    assert_in_delta 0.1, b.received.first.last
    assert_in_delta 0.2, a.received.first.last
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

  # A timer run out can set another that is due at once; it runs out too,
  # in the same instant.
  def test_a_timer_that_sets_another_due_at_once
    net = Test::Network.new(seed: 1)
    node = net.add(Chained.new, address: A)
    net.advance(2.0)
    assert_equal [[1.0, 1.0], [0.5, 1.0]], node.handled
  end
end
