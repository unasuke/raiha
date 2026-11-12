require "raiha/next/test_helper"
require "raiha/next/runtime"
require "raiha/next/support/quic_tls"
require "async"

# The driver of the runtime runs an Endpoint on a UDP socket of the
# loopback interface in fibers of the scheduler: a client and a server each
# on one complete a handshake, and the timers of the core run with no
# datagram to wake them.
class RaihaNextRuntimeDriverTest < Minitest::Test
  include NextQUICTLS

  Runtime = Raiha::Next::Runtime

  # What a client or a server of the runtime would be to the driver: a
  # server takes every client, and the events are let go.
  class Owner
    QUIC = Raiha::Next::QUIC

    attr_reader :connections, :stopped_with, :turns

    def initialize(endpoint, tls_config: nil, keyring: nil, fail_on_turn: false)
      @endpoint = endpoint
      @tls_config = tls_config
      @keyring = keyring
      @fail_on_turn = fail_on_turn
      @connections = []
      @turns = 0
      @stopped_with = :running
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
    end

    def next_timeout = nil

    def stopped(failure)
      @stopped_with = failure
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
    endpoint = QUIC::Endpoint.server(config: QUIC::Config.new, random: SecureRandom, time: Time.now, now: Runtime::Driver.clock)
    owner = Owner.new(endpoint, tls_config:, keyring: server_keyring(config: tls_config))
    [Runtime::Driver.new(endpoint, Runtime::UDP.bind("127.0.0.1", 0), owner), owner]
  end

  # A client's driver with a connection to `driver`'s port.
  def client(to, config: QUIC::Config.new)
    endpoint = QUIC::Endpoint.client(config:, random: SecureRandom, time: Time.now, now: Runtime::Driver.clock)
    owner = Owner.new(endpoint)
    driver = Runtime::Driver.new(endpoint, Runtime::UDP.bind("127.0.0.1", 0), owner)
    tls_config = client_config
    owner.connections << endpoint.connect(tls_config:, keyring: client_keyring(config: tls_config), server_name: "localhost",
      remote: ["127.0.0.1", to], now: Runtime::Driver.clock)
    [driver, owner]
  end

  def port(driver) = driver.instance_variable_get(:@udp).local_address[1]

  # Sleeps a little at a time until the block is true, for `seconds` at
  # most: whether it came true.
  def eventually(seconds: 5)
    limit = Runtime::Driver.clock + seconds
    sleep 0.01 until yield || Runtime::Driver.clock > limit
    yield
  end

  def test_a_scheduler_is_needed
    driver, = server
    assert_raises(Runtime::Error::Usage) { driver.start }
  ensure
    driver&.stop
  end

  def test_a_handshake_over_the_loopback
    Sync do
      server_driver, server_owner = server
      client_driver, client_owner = client(port(server_driver.start))
      client_driver.start
      assert eventually { client_owner.connections.first.handshake_complete? && server_owner.connections.first&.handshake_complete? }
      client_driver.stop
      server_driver.stop
      assert_nil client_driver.failure
      assert_nil server_driver.failure
      assert_nil server_owner.stopped_with
    end
  end

  # With the server gone, nothing comes to wake the client, and the idle
  # timeout still closes its connection.
  def test_the_timers_run_with_no_datagram
    Sync do
      server_driver, = server
      client_driver, client_owner = client(port(server_driver.start), config: QUIC::Config.new(max_idle_timeout: 0.3))
      client_driver.start
      connection = client_owner.connections.first
      assert eventually { connection.handshake_complete? }
      server_driver.stop
      assert eventually(seconds: 3) { connection.closed? }
      client_driver.stop
    end
  end

  # What fails in the runner stops the driver and is told to the owner,
  # not lost in a fiber that ends.
  def test_a_failure_stops_the_driver
    Sync do
      endpoint = QUIC::Endpoint.client(config: QUIC::Config.new, random: SecureRandom, time: Time.now, now: Runtime::Driver.clock)
      owner = Owner.new(endpoint, fail_on_turn: true)
      driver = Runtime::Driver.new(endpoint, Runtime::UDP.bind("127.0.0.1", 0), owner).start
      driver.changed
      assert eventually { driver.stopped? }
      assert_equal "a turn that fails", driver.failure&.message
      assert_same driver.failure, owner.stopped_with
    end
  end

  # With a socket besides, as a server's preferred address has: what comes
  # to it goes to the Endpoint, and a Transmit goes from the socket of its
  # source, the first when it has none.
  def test_another_socket
    Sync do
      endpoint = Recorder.new
      first = Runtime::UDP.bind("127.0.0.1", 0)
      second = Runtime::UDP.bind("127.0.0.1", 0)
      driver = Runtime::Driver.new(endpoint, first, Owner.new(endpoint), others: [second]).start
      peer = UDPSocket.new
      peer.bind("127.0.0.1", 0)
      peer.send("to the second", 0, *second.local_address)
      assert eventually { endpoint.received.any? }
      assert_equal [["to the second", second.local_address]], endpoint.received
      to = ["127.0.0.1", peer.local_address.ip_port]
      endpoint.push(QUIC::Transmit.new(payload: "from the second", destination: to, source: second.local_address, ecn: :not_ect,
        segment_size: nil))
      endpoint.push(QUIC::Transmit.new(payload: "from the first", destination: to, source: nil, ecn: :not_ect, segment_size: nil))
      driver.changed
      got = 2.times.map { data, from = peer.recvfrom(100); [data, from[1]] }
      assert_equal [["from the first", first.local_address[1]], ["from the second", second.local_address[1]]], got.sort
      driver.stop
      assert second.closed?
    ensure
      peer&.close
    end
  end

  # An Endpoint of worker 0 that routes "theirs" to worker 1, and keeps what
  # it is given with whether it was handed on and when it came.
  class Router < Recorder
    def receive(data, from:, to:, ecn:, now:, forwarded: false)
      return Raiha::Next::QUIC::Route::Foreign.new(worker: 1, datagram: data) if data == "theirs" && !forwarded
      @received << [data, forwarded, now]
      nil
    end
  end

  # A worker's driver hands on what its Endpoint routes to another worker,
  # with where and when it came, and gives its Endpoint what another worker
  # handed on, as it came then and never to be handed on again.
  def test_a_worker_hands_on_and_takes
    Sync do
      inboxes = Array.new(2) { Ractor::Port.new }
      workers = Array.new(2) { |id| Runtime::Worker.new(id:, count: 2, sockets: [], inbox: inboxes[id], control: Ractor::Port.new, peers: inboxes) }
      endpoint = Router.new
      udp = Runtime::UDP.bind("127.0.0.1", 0)
      driver = Runtime::Driver.new(endpoint, udp, Owner.new(endpoint), worker: workers[0]).start
      workers[0].listen(changed: -> { driver.changed }, failed: ->(_error) { nil }) { nil }
      workers[1].listen(changed: -> { nil }, failed: ->(_error) { nil }) { nil }
      peer = UDPSocket.new
      peer.bind("127.0.0.1", 0)
      peer.send("theirs", 0, *udp.local_address)
      handed = []
      assert eventually { handed.concat(workers[1].take).any? }
      data, from, to, ecn, received_at = handed.first
      assert_equal ["theirs", ["127.0.0.1", peer.local_address.ip_port], udp.local_address, :not_ect], [data, from, to, ecn]
      assert_kind_of Float, received_at
      workers[1].forward(0, ["mine".b, ["127.0.0.1", 1], nil, :not_ect, 12.5])
      assert eventually { endpoint.received.any? }
      assert_equal [["mine", true, 12.5]], endpoint.received
      driver.stop
    ensure
      peer&.close
      workers&.each(&:close)
    end
  end
end
