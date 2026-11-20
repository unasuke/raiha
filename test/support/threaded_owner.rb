require "raiha/runtime"
require "support/quic_tls"
require "securerandom"

# A stand-in for a client or a server of the runtime on threads, for tests
# of what lies under them: an Endpoint on a UDP socket of the loopback
# interface, run by a Threaded::Driver, with each connection in a
# Threaded::Session.
module ThreadedOwner
  include QUICTLS

  Runtime = Raiha::Runtime
  Threaded = Raiha::Runtime::Threaded

  # What a client or a server of the runtime would be to its driver: a
  # server takes every client, and each connection is in a Session, which
  # takes its turn with the driver's, under its lock. The streams of
  # `each_stream` have `max_threads` threads at a time.
  class Owner
    QUIC = Raiha::QUIC

    attr_reader :sessions, :turns, :threads
    attr_accessor :driver

    def initialize(endpoint, role, tls_config: nil, keyring: nil, max_threads: 64)
      @endpoint = endpoint
      @role = role
      @tls_config = tls_config
      @keyring = keyring
      @threads = Threaded::Threads.new(max_threads)
      @sessions = []
      @turns = 0
    end

    def add(connection) = @sessions << Threaded::Session.new(connection, driver, role: @role, threads: @threads)

    # The port of its socket.
    def port = driver.instance_variable_get(:@udp).local_address[1]

    def route(route, now)
      case route
      when QUIC::Route::Incoming then (hello = @endpoint.admit(route.handle, now:)) && route(hello, now)
      when QUIC::Route::ClientHello then add(@endpoint.accept(route.handle, tls_config: @tls_config, keyring: @keyring, now:))
      end
    end

    def turn(_now)
      @turns += 1
      @sessions.each(&:turn)
    end

    def next_timeout = nil

    def stopped(failure) = @sessions.each { _1.abort(failure) }

    def flush_traces = nil
  end

  # [endpoint, owner] of `role` with `config`, its driver not yet started.
  def owner(role, config, **options)
    endpoint = (role == :server ? QUIC::Endpoint.method(:server) : QUIC::Endpoint.method(:client))
      .call(config:, random: SecureRandom, time: Time.now, now: Threaded::Driver.clock)
    owner = Owner.new(endpoint, role, **options)
    owner.driver = Threaded::Driver.new(endpoint, Runtime::UDP.bind("127.0.0.1", 0), owner)
    [endpoint, owner]
  end

  # A server's Owner with the test certificate, its driver started.
  def server_owner(config = QUIC::Config.new, tls: server_config, **options)
    _, owner = owner(:server, config, tls_config: tls, keyring: server_keyring(config: tls), **options)
    owner.driver.start
    owner
  end

  # The first Session `owner` has, once it has one.
  def accepted(owner)
    sleep 0.01 until owner.sessions.first
    owner.sessions.first
  end

  # Sleeps a little at a time until the block is true, for `seconds` at
  # most: whether it came true.
  def eventually(seconds: 5)
    limit = Threaded::Driver.clock + seconds
    sleep 0.01 until yield || Threaded::Driver.clock > limit
    yield
  end
end
