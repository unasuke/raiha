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
end
