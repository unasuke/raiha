require "raiha/runtime"
require "support/quic_tls"
require "securerandom"

# A stand-in for a client or a server of the runtime of the next release,
# for tests of what lies under them: an Endpoint on a UDP socket of the
# loopback interface, run by a Driver, with each connection in a Session.
module NextRuntimeOwner
  include NextQUICTLS

  Runtime = Raiha::Next::Runtime

  # A port no socket is bound to, as far as anyone knows.
  def free_port = UDPSocket.open { |socket| socket.bind("127.0.0.1", 0) && socket.addr[1] }

  # What a client or a server of the runtime would be to its driver: a
  # server takes every client, and each connection is in a Session, which
  # takes its turn with the driver's.
  class Owner
    QUIC = Raiha::Next::QUIC

    attr_reader :sessions, :turns
    attr_accessor :driver

    def initialize(endpoint, role, tls_config: nil, keyring: nil, anti_replay: nil)
      @endpoint = endpoint
      @role = role
      @tls_config = tls_config
      @keyring = keyring
      @anti_replay = anti_replay
      @sessions = []
      @turns = 0
    end

    def add(connection) = @sessions << Runtime::Session.new(connection, driver, role: @role)

    # The port of its socket.
    def port = driver.instance_variable_get(:@udp).local_address[1]

    def route(route, now)
      case route
      when QUIC::Route::Incoming then (hello = @endpoint.admit(route.handle, now:)) && route(hello, now)
      when QUIC::Route::ClientHello
        add(@endpoint.accept(route.handle, tls_config: @tls_config, keyring: @keyring, anti_replay: @anti_replay, now:))
      end
    end

    def turn(_now)
      @turns += 1
      @sessions.each(&:turn)
    end

    def next_timeout = nil

    def stopped(failure) = @sessions.each { _1.abort(failure) }
  end

  # [endpoint, owner] of `role` with `config`, its driver not yet started.
  def owner(role, config, **options)
    endpoint = (role == :server ? QUIC::Endpoint.method(:server) : QUIC::Endpoint.method(:client))
      .call(config:, random: SecureRandom, time: Time.now, now: Runtime::Driver.clock)
    owner = Owner.new(endpoint, role, **options)
    owner.driver = Runtime::Driver.new(endpoint, Runtime::UDP.bind("127.0.0.1", 0), owner)
    [endpoint, owner]
  end

  # A server's Owner with the test certificate, its driver started.
  def server_owner(config = QUIC::Config.new, tls: server_config, anti_replay: nil)
    _, owner = owner(:server, config, tls_config: tls, keyring: server_keyring(config: tls), anti_replay:)
    owner.driver.start
    owner
  end

  # The first Session `owner` has, once it has one.
  def accepted(owner)
    sleep 0.01 until owner.sessions.first
    owner.sessions.first
  end
end
