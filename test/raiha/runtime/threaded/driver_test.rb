require "test_helper"
require "raiha/runtime"
require "support/quic_tls"

# The driver of the runtime on threads runs an Endpoint on a UDP socket of
# the loopback interface with threads of its own, no scheduler needed: a
# client and a server each on one complete a handshake, the timers run
# with no datagram to wake them, and what is sent under the lock goes once
# it is let go.
class RaihaRuntimeThreadedDriverTest < Minitest::Test
  include QUICTLS

  Runtime = Raiha::Runtime
  Threaded = Raiha::Runtime::Threaded

  # What a client or a server of the runtime would be to the driver: a
  # server takes every client, and the events are let go. With `on_turn`,
  # each turn calls it with the driver, under the lock.
  class Owner
    QUIC = Raiha::QUIC

    attr_reader :connections, :stopped_with, :turns, :stops, :traces_flushed
    attr_accessor :driver, :on_turn

    def initialize(endpoint, tls_config: nil, keyring: nil, fail_on_turn: false)
      @endpoint = endpoint
      @tls_config = tls_config
      @keyring = keyring
      @fail_on_turn = fail_on_turn
      @connections = []
      @turns = 0
      @stops = 0
      @traces_flushed = 0
      @stopped_with = :running
      @driver = nil
      @on_turn = nil
    end

    def route(route, now)
      case route
      when QUIC::Route::Incoming then (hello = @endpoint.admit(route.handle, now:)) && route(hello, now)
      when QUIC::Route::ClientHello then @connections << @endpoint.accept(route.handle, tls_config: @tls_config, keyring: @keyring, now:)
      end
    end

    def turn(_now)
      raise "a turn that fails" if @fail_on_turn && @turns.positive?
      @turns += 1
      @connections.each { |connection| connection.each_event { nil } }
      @on_turn&.call(@driver)
    end

    def next_timeout = nil

    def stopped(failure)
      @stops += 1
      @stopped_with = failure
    end

    def flush_traces
      @traces_flushed += 1
    end
  end

  # An Endpoint that keeps each datagram with the address it came to, and
  # sends what it is given.
  class Recorder
    attr_reader :received

    def initialize
      @received = []
      @transmits = []
    end

    def receive(data, from:, to:, ecn:, now:)
      @received << [data, to]
      nil
    end

    def each_transmit(now:)
      yield @transmits.shift until @transmits.empty?
    end

    def next_timeout = nil

    def handle_timeout(now:) = nil

    def push(transmit) = @transmits << transmit
  end

  def server
    tls_config = server_config
    endpoint = QUIC::Endpoint.server(config: QUIC::Config.new, random: SecureRandom, time: Time.now, now: Threaded::Driver.clock)
    owner = Owner.new(endpoint, tls_config:, keyring: server_keyring(config: tls_config))
    [owner.driver = Threaded::Driver.new(endpoint, Runtime::UDP.bind("127.0.0.1", 0), owner), owner]
  end

  # A client's driver with a connection to `driver`'s port.
  def client(to, config: QUIC::Config.new)
    endpoint = QUIC::Endpoint.client(config:, random: SecureRandom, time: Time.now, now: Threaded::Driver.clock)
    owner = Owner.new(endpoint)
    driver = owner.driver = Threaded::Driver.new(endpoint, Runtime::UDP.bind("127.0.0.1", 0), owner)
    tls_config = client_config
    owner.connections << endpoint.connect(tls_config:, keyring: client_keyring(config: tls_config), server_name: "localhost",
      remote: ["127.0.0.1", to], now: Threaded::Driver.clock)
    [driver, owner]
  end

  # A driver of a Recorder, and a peer socket to send it datagrams and take
  # what it sends.
  def recorded
    endpoint = Recorder.new
    owner = Owner.new(endpoint)
    udp = Runtime::UDP.bind("127.0.0.1", 0)
    driver = owner.driver = Threaded::Driver.new(endpoint, udp, owner)
    peer = UDPSocket.new
    peer.bind("127.0.0.1", 0)
    [driver, owner, endpoint, peer]
  end

  def transmit(payload, peer) = QUIC::Transmit.new(payload:, destination: ["127.0.0.1", peer.local_address.ip_port], source: nil,
    ecn: :not_ect, segment_size: nil)

  def port(driver) = driver.instance_variable_get(:@udp).local_address[1]

  # Sleeps a little at a time until the block is true, for `seconds` at
  # most: whether it came true.
  def eventually(seconds: 5)
    limit = Threaded::Driver.clock + seconds
    sleep 0.01 until yield || Threaded::Driver.clock > limit
    yield
  end

  def test_a_handshake_with_no_scheduler
    assert_nil Fiber.scheduler
    server_driver, server_owner = server
    client_driver, client_owner = client(port(server_driver.start))
    client_driver.start
    assert eventually { client_owner.connections.first.handshake_complete? && server_owner.connections.first&.handshake_complete? }
    client_driver.stop
    server_driver.stop
    [client_driver, server_driver].each(&:join)
    assert_nil client_driver.failure
    assert_nil server_driver.failure
    assert_nil server_owner.stopped_with
  end

  def test_the_threads_have_names
    server_driver, = server
    server_driver.start
    names = [*server_driver.instance_variable_get(:@readers), server_driver.instance_variable_get(:@runner)].map(&:name)
    assert_equal %w[raiha-reader raiha-runner], names
  ensure
    server_driver&.stop
    server_driver&.join
  end

  # With the server gone, nothing comes to wake the client, and the idle
  # timeout still closes its connection.
  def test_the_timers_run_with_no_datagram
    server_driver, = server
    client_driver, client_owner = client(port(server_driver.start), config: QUIC::Config.new(max_idle_timeout: 0.3))
    client_driver.start
    connection = client_owner.connections.first
    assert eventually { connection.handshake_complete? }
    server_driver.stop
    assert eventually(seconds: 3) { client_driver.synchronize { connection.closed? } }
  ensure
    client_driver&.stop
    [client_driver, server_driver].each { _1&.join }
  end

  # What fails in the runner stops the driver and is told to the owner,
  # not lost in a thread that ends.
  def test_a_failure_stops_the_driver
    endpoint = QUIC::Endpoint.client(config: QUIC::Config.new, random: SecureRandom, time: Time.now, now: Threaded::Driver.clock)
    owner = Owner.new(endpoint, fail_on_turn: true)
    driver = Threaded::Driver.new(endpoint, Runtime::UDP.bind("127.0.0.1", 0), owner).start
    driver.changed
    assert eventually { driver.stopped? }
    driver.join
    assert_equal "a turn that fails", driver.failure&.message
    assert_same driver.failure, owner.stopped_with
  end

  # With a socket besides, as a server's preferred address has: what comes
  # to it goes to the Endpoint, and a Transmit goes from the socket of its
  # source, the first when it has none.
  def test_another_socket
    endpoint = Recorder.new
    first = Runtime::UDP.bind("127.0.0.1", 0)
    second = Runtime::UDP.bind("127.0.0.1", 0)
    driver = Threaded::Driver.new(endpoint, first, Owner.new(endpoint), others: [second]).start
    peer = UDPSocket.new
    peer.bind("127.0.0.1", 0)
    peer.send("to the second", 0, *second.local_address)
    assert eventually { driver.synchronize { endpoint.received.any? } }
    assert_equal [["to the second", second.local_address]], endpoint.received
    to = ["127.0.0.1", peer.local_address.ip_port]
    driver.synchronize do
      endpoint.push(QUIC::Transmit.new(payload: "from the second", destination: to, source: second.local_address, ecn: :not_ect,
        segment_size: nil))
      endpoint.push(QUIC::Transmit.new(payload: "from the first", destination: to, source: nil, ecn: :not_ect, segment_size: nil))
    end
    driver.changed
    got = 2.times.map { data, from = peer.recvfrom(100); [data, from[1]] }
    assert_equal [["from the first", first.local_address[1]], ["from the second", second.local_address[1]]], got.sort
    driver.stop
    driver.join
    assert second.closed?
  ensure
    peer&.close
  end

  # A flush from the owner's turn holds the lock, so what it takes goes
  # from the runner once the turn is over, before what the turn has.
  def test_a_flush_under_the_lock_goes_after_the_turn
    driver, owner, endpoint, peer = recorded
    owner.on_turn = lambda do |turning|
      next unless owner.turns == 2
      endpoint.push(transmit("flushed", peer))
      turning.flush
      endpoint.push(transmit("of the turn", peer))
    end
    driver.start
    driver.changed
    got = 2.times.map { peer.recvfrom(100).first }
    assert_equal ["flushed", "of the turn"], got
  ensure
    driver&.stop
    driver&.join
    peer&.close
  end

  # A flush with no lock held sends from the thread that calls it.
  def test_a_flush_from_another_thread
    driver, _owner, endpoint, peer = recorded
    driver.start
    driver.synchronize { endpoint.push(transmit("flushed", peer)) }
    driver.flush
    assert_equal "flushed", peer.recvfrom(100).first
  ensure
    driver&.stop
    driver&.join
    peer&.close
  end

  # A stop in the owner's turn leaves the sockets open until what the turn
  # had to send has gone; the owner is told once and writes its traces.
  def test_a_stop_in_the_turn_sends_what_is_left
    driver, owner, endpoint, peer = recorded
    owner.on_turn = lambda do |turning|
      next unless owner.turns == 2
      endpoint.push(transmit("last", peer))
      turning.flush
      turning.stop
    end
    driver.start
    driver.changed
    assert_equal "last", peer.recvfrom(100).first
    driver.join
    assert driver.instance_variable_get(:@udp).closed?
    assert_equal [1, nil], [owner.stops, owner.stopped_with]
    assert_operator owner.traces_flushed, :>=, 1
  end

  # Stops from several threads at once tell the owner once.
  def test_stops_from_several_threads
    driver, owner, _endpoint, peer = recorded
    driver.start
    8.times.map { Thread.new { driver.stop } }.each(&:join)
    driver.join
    assert_equal 1, owner.stops
    assert driver.instance_variable_get(:@udp).closed?
  ensure
    peer&.close
  end
end
