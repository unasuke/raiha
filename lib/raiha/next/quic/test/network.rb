# frozen_string_literal: true

module Raiha::Next::QUIC::Test
  # A datagram on its way through a network: what models pass along, and
  # mark with CE.
  class Datagram < Data.define(:payload, :source, :destination, :ecn); end

  # Endpoints and connections wired together on a virtual clock, so that a
  # handshake or a transfer runs with no socket and no real time. A node is
  # anything with `receive(payload, from:, to:, ecn:, now:)`,
  # `each_transmit(now:)`, `next_timeout` and `handle_timeout(now:)`, added at
  # an address; what it sends goes to the node at the destination address.
  # A node can have more addresses, and sends from the one a Transmit names
  # as its source. An address can be put behind a NAT, which gives what is
  # sent from it another source address.
  #
  # Between two nodes a link puts a path model, or an array of them in order:
  # a value whose `start(random:)` gives the state of one direction, with
  # `submit(datagram, now:)`, `each_delivery(now:)` and `next_timeout`. The
  # randomness of each direction comes from `seed:`, so a failure happens
  # again on the same seed. Without a link, datagrams arrive at once.
  class Network
    # How many rounds of sending and delivering one instant may take before
    # the network is taken to be stuck there.
    MAX_ROUNDS = 10_000

    # A node or a path keeps asking for an instant that has passed, or
    # keeps sending at one: time cannot go on.
    class Stuck < StandardError; end

    attr_reader :clock

    def initialize(seed:, clock: VirtualClock.new)
      @random = Random.new(seed)
      @clock = clock
      @nodes = {} #: Hash[Raiha::Next::QUIC::address, _Node]
      @addresses = {} #: Hash[_Node, Raiha::Next::QUIC::address]
      @addresses.compare_by_identity
      @links = {} #: Hash[[Raiha::Next::QUIC::address, Raiha::Next::QUIC::address], _Path]
      @outside = {} #: Hash[Raiha::Next::QUIC::address, Raiha::Next::QUIC::address]
      @inside = {} #: Hash[Raiha::Next::QUIC::address, Raiha::Next::QUIC::address]
      @direct = Direct.new
    end

    def now = @clock.now

    # Puts `node` on the network at `address` ([host, port]) and gives it
    # back.
    def add(node, address:)
      take(address, node)
      @addresses[node] = address
      node
    end

    # The address `node` was added at.
    def address_of(node) = @addresses.fetch(node)

    # Gives `node`, already on the network, another address, as a server's
    # second address it offers as its preferred address.
    def add_address(node, address:)
      address_of(node)
      take(address, node)
      self
    end

    # Puts a node's address `inside` behind a NAT, or changes the NAT's
    # binding: from now on, what the node sends from `inside` leaves from
    # `to`, and what comes to `to` reaches the node at `inside`. What comes
    # to the address it was seen at before is lost, as when a NAT has
    # dropped the binding.
    def rebind(inside, to:)
      raise ArgumentError, "no node is at #{inside.inspect}" unless @nodes.key?(inside)
      raise ArgumentError, "#{to.inspect} is taken" if @nodes.key?(to) || @inside.key?(to)
      @inside.delete(@outside[inside])
      @outside[inside] = to
      @inside[to] = inside
      self
    end

    # Puts a server's Endpoint on the network at `address`, run by a
    # Test::Server that takes every offer with `tls_config` and `keyring`,
    # and gives the Test::Server. `time` is the wall clock the Endpoint
    # starts at; its random bytes come from the seed.
    def add_server(config:, tls_config:, keyring:, time:, address:, **options)
      endpoint = Raiha::Next::QUIC::Endpoint.server(config:, random: Random.new(@random.rand(1 << 64)), time:, now:)
      add(Server.new(endpoint, tls_config:, keyring:, **options), address:)
    end

    # Links two nodes with `model` both ways, or with `forward` from `a` to
    # `b` and `reverse` back.
    def link(a, b, model: nil, forward: model, reverse: model)
      from = address_of(a)
      to = address_of(b)
      @links[[from, to]] = start(forward) if forward
      @links[[to, from]] = start(reverse) if reverse
      self
    end

    # Runs until the block is true, and gives true; or gives false once
    # nothing is left to happen or `within` seconds have passed.
    def run_until(within: 60.0)
      deadline = now + within
      loop do
        settle
        return true if yield
        time = next_event
        return false if time.nil? || time > deadline
        @clock.advance_to(time)
      end
    end

    # Lets `seconds` go by, with everything that happens in them.
    def advance(seconds)
      target = now + seconds
      loop do
        settle
        time = next_event
        break if time.nil? || time > target
        @clock.advance_to(time)
      end
      @clock.advance_to(target)
      settle
    end

    # Everything due at this instant: timers run out, datagrams sent and
    # delivered, until nothing more happens. A timer run out can set
    # another that is due at once, as a PTO after a loss timer may be.
    private def settle
      MAX_ROUNDS.times do
        moved = false
        @addresses.each_key do |node|
          timeout = node.next_timeout
          next unless timeout && timeout <= now
          moved = true
          node.handle_timeout(now:)
        end
        @addresses.each_key do |node|
          node.each_transmit(now:) do |transmit|
            moved = true
            transmit_from(node, transmit)
          end
        end
        each_path do |path|
          path.each_delivery(now:) do |datagram|
            moved = true
            deliver(datagram)
          end
        end
        return unless moved
      end
      raise Stuck, "still sending at #{now}"
    end

    # Sends from the address the Transmit names, or the one the node was
    # added at, which the NAT the node is behind changes; over the link
    # between the node and the one at the destination, whichever addresses
    # they use.
    private def transmit_from(node, transmit)
      source = transmit.source || address_of(node)
      raise ArgumentError, "#{source.inspect} is not an address of the node" unless @nodes[source].equal?(node) # steep:ignore
      payload = transmit.payload
      size = transmit.segment_size || payload.bytesize
      receiver = (to = inside(transmit.destination)) && @nodes[to]
      path = receiver ? @links.fetch([address_of(node), address_of(receiver)], @direct) : @direct
      source = @outside.fetch(source, source)
      0.step(payload.bytesize - 1, size) do |offset|
        path.submit(Datagram.new(payload: payload.byteslice(offset, size), source:, destination: transmit.destination, ecn: transmit.ecn), now:) # steep:ignore
      end
    end

    private def deliver(datagram)
      to = inside(datagram.destination) or return
      node = @nodes[to] or return
      node.receive(datagram.payload, from: datagram.source, to:, ecn: datagram.ecn, now:)
    end

    # The address on the network a datagram to `address` reaches: through
    # the NAT, or none for an address the NAT hides.
    private def inside(address) = @inside.fetch(address) { address unless @outside.key?(address) }

    private def take(address, node)
      raise ArgumentError, "#{address.inspect} is taken" if @nodes.key?(address) || @inside.key?(address)
      @nodes[address] = node
    end

    private def each_path(&)
      yield @direct
      @links.each_value(&)
    end

    # When something happens next, after everything due now has happened.
    private def next_event
      times = @addresses.each_key.filter_map(&:next_timeout)
      each_path { |path| (time = path.next_timeout) && times << time }
      time = times.min
      raise Stuck, "#{time} is still due at #{now}" if time && time <= now
      time
    end

    private def start(model)
      random = Random.new(@random.rand(1 << 64))
      case model
      when Array then Chain.new(model.map { |stage| stage.start(random: Random.new(random.rand(1 << 64))) })
      else model.start(random:)
      end
    end

    # Datagrams without a link: delivered at once.
    class Direct
      def initialize
        @queue = [] #: Array[Datagram]
      end

      def submit(datagram, now:) = @queue << datagram

      def each_delivery(now:)
        queue = @queue
        @queue = []
        queue.each { |datagram| yield datagram }
      end

      # Nothing waits: what is submitted is delivered in the same instant.
      def next_timeout = nil
    end

    # Models one after another: what leaves one enters the next at once.
    class Chain
      def initialize(stages)
        @stages = stages
      end

      def submit(datagram, now:) = @stages.fetch(0).submit(datagram, now:)

      def each_delivery(now:, &)
        @stages.each_cons(2) do |stage, following|
          stage.each_delivery(now:) { |datagram| following.submit(datagram, now:) } # steep:ignore
        end
        @stages.fetch(-1).each_delivery(now:, &)
      end

      def next_timeout = @stages.filter_map(&:next_timeout).min
    end
  end
end
