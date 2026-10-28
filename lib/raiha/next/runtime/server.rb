# frozen_string_literal: true

require "securerandom"

module Raiha::Next::Runtime
  # The server of the runtime: an Endpoint on a UDP socket of its own that
  # takes every client up to `max_connections` at a time, refusing more
  # with CONNECTION_REFUSED, and gives the block of `run` the Session of
  # each connection once its handshake completes, in a fiber of its own.
  #
  # When the block is over, what the streams sent is given three PTOs to be
  # acknowledged and the connection closes with the application's error 0;
  # when it raises, the connection closes with INTERNAL_ERROR, and the
  # exception goes on to the scheduler. Other connections are not touched.
  class Server
    MAX_CONNECTIONS = 1024

    def initialize(config:, tls_config:, keyring:, host: "::", port: 443, max_connections: MAX_CONNECTIONS)
      @config = config
      @tls_config = tls_config
      @keyring = keyring
      @host = host
      @port = port
      @max_connections = max_connections
      # The sessions of the connections taken, and those given to the block.
      @sessions = [] #: Array[Session]
      @started = {} #: Hash[Session, true]
      @started.compare_by_identity
      @handler = nil #: ^(Session) -> void | nil
      @driver = nil #: Driver?
      @udp = nil #: UDP?
      @lock = Thread::Mutex.new
      @stopped = Thread::ConditionVariable.new
    end

    # Binds the socket and serves until stopped, giving the block each
    # Session; raises what failed in the driver, if anything did.
    def run(&handler)
      raise Error::Usage, "the runtime waits through a Fiber scheduler; this thread has none" unless Fiber.scheduler
      @handler = handler
      udp = @udp = UDP.bind(@host, @port)
      endpoint = Raiha::Next::QUIC::Endpoint.server(config: @config, random: SecureRandom, time: Time.now, now: Driver.clock)
      driver = @driver = Driver.new(endpoint, udp, self).start
      @lock.synchronize { @stopped.wait(@lock) until driver.stopped? }
      failure = driver.failure and raise failure
      nil
    end

    # [address, port] the socket is bound to, once `run` has bound it.
    def local_address = @udp&.local_address

    # Stops serving now: the socket closes, and what waits on a session
    # raises QUIC::ClosedError.
    def stop
      @driver&.stop
    end

    # The driver's owner: a new connection is taken while there is room for
    # it.
    def route(route, now)
      endpoint = @driver&.endpoint or return
      case route
      when Raiha::Next::QUIC::Route::Incoming
        return endpoint.refuse(route.handle) if @sessions.size >= @max_connections
        hello = endpoint.admit(route.handle, now:) and route(hello, now)
      when Raiha::Next::QUIC::Route::ClientHello
        connection = endpoint.accept(route.handle, tls_config: @tls_config, keyring: @keyring, now:)
        @sessions << Session.new(connection, driver!, role: :server)
      end
    end

    # The driver's turn: each Session's, the block for each whose handshake
    # has completed, and the sessions of connections over let go.
    def turn(_now)
      @sessions.each do |session|
        session.turn
        start(session) if !@started.key?(session) && session.connection.handshake_complete?
      end
      over = @sessions.select { |session| session.connection.closed? }
      over.each { |session| @started.delete(session) }
      @sessions -= over
    end

    def next_timeout = nil

    def stopped(failure)
      @sessions.each { |session| session.abort(failure) }
      @lock.synchronize { @stopped.broadcast }
    end

    private def driver! = @driver || raise(Error::Usage, "the server is not running")

    private def start(session)
      @started[session] = true
      handler = @handler or return
      Fiber.schedule do
        handler.call(session)
        session.close_when_acknowledged
      rescue Raiha::Next::QUIC::ClosedError
        nil
      rescue StandardError
        session.connection.close(error_code: Raiha::Next::QUIC::ErrorCode::INTERNAL_ERROR, application: false, now: Driver.clock)
        driver!.changed
        raise
      end
    end

  end
end
