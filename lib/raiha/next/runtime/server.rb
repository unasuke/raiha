# frozen_string_literal: true

require "securerandom"

module Raiha::Next::Runtime
  # The server of the runtime: an Endpoint on a UDP socket of its own that
  # takes every client up to `max_connections` at a time, refusing more
  # with CONNECTION_REFUSED, and gives the block of `run` the Session of
  # each connection once its handshake completes, in a fiber of its own.
  # Once half of them are taken, a client whose address no Retry has shown
  # yet is sent one first, so that Initials from addresses spoofed by the
  # thousand cannot take the rest.
  #
  # When the block is over, what the streams sent is given three PTOs to be
  # acknowledged and the connection closes with the application's error 0;
  # when it raises, the connection closes with INTERNAL_ERROR, and the
  # exception goes on to the scheduler. Other connections are not touched.
  #
  # `stop` asks the server to stop, from a signal handler as well: no new
  # connection is taken, each Session is told it is `stopping?`, and the
  # sessions are given `timeout` seconds to end their connections and wait
  # out the closing period; those left are closed with the application's
  # `error_code`. `run` returns then.
  class Server
    MAX_CONNECTIONS = 1024
    STOP_TIMEOUT = 30

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
      # What `stop` asked, [timeout, error_code], when it was asked, and
      # when the sessions are out of time; and the pipe that wakes the
      # driver for it.
      @stop = nil #: [Float | Integer, Integer]?
      @stop_deadline = nil #: Float?
      @wake = nil #: IO?
    end

    # Binds the socket and serves until stopped, giving the block each
    # Session; raises what failed in the driver, if anything did.
    def run(&handler)
      raise Error::Usage, "the runtime waits through a Fiber scheduler; this thread has none" unless Fiber.scheduler
      @handler = handler
      udp = @udp = UDP.bind(@host, @port)
      endpoint = Raiha::Next::QUIC::Endpoint.server(config: @config, random: SecureRandom, time: Time.now, now: Driver.clock)
      driver = @driver = Driver.new(endpoint, udp, self).start
      reader, @wake = IO.pipe
      Fiber.schedule { wake_on(reader, driver) }
      @lock.synchronize { @stopped.wait(@lock) until driver.stopped? }
      failure = driver.failure and raise failure
      nil
    ensure
      reader&.close
      @wake&.close
    end

    # [address, port] the socket is bound to, once `run` has bound it.
    def local_address = @udp&.local_address

    # Asks the server to stop, giving the sessions `timeout` seconds; the
    # first call is the one that counts. It takes no lock and writes to a
    # pipe without waiting, so a signal handler may call it.
    def stop(timeout: STOP_TIMEOUT, error_code: 0)
      @stop ||= [timeout, error_code]
      @wake&.write_nonblock(".", exception: false)
      nil
    rescue IOError
      # `run` has returned and closed the pipe.
      nil
    end

    # The driver's owner: a new connection is taken while there is room for
    # it.
    def route(route, now)
      endpoint = @driver&.endpoint or return
      case route
      when Raiha::Next::QUIC::Route::Incoming
        return endpoint.refuse(route.handle) if @stop || @sessions.size >= @max_connections
        return endpoint.retry(route.handle, now:) if !route.address_validated && @sessions.size * 2 >= @max_connections
        hello = endpoint.admit(route.handle, now:) and route(hello, now)
      when Raiha::Next::QUIC::Route::ClientHello
        connection = endpoint.accept(route.handle, tls_config: @tls_config, keyring: @keyring, now:)
        @sessions << Session.new(connection, driver!, role: :server)
      end
    end

    # The driver's turn: each Session's, the block for each whose handshake
    # has completed, and the sessions of connections over let go.
    def turn(now)
      @sessions.each do |session|
        session.turn
        start(session) if !@stop && !@started.key?(session) && session.connection.handshake_complete?
      end
      over = @sessions.select { |session| session.connection.closed? }
      over.each { |session| @started.delete(session) }
      @sessions -= over
      stopping(now) if @stop
    end

    def next_timeout = @stop_deadline

    def stopped(failure)
      @sessions.each { |session| session.abort(failure) }
      @lock.synchronize { @stopped.broadcast }
    end

    private def driver! = @driver || raise(Error::Usage, "the server is not running")

    # Has the driver go round each time `stop` writes to the pipe.
    private def wake_on(reader, driver)
      until driver.stopped?
        reader.wait_readable
        reader.read_nonblock(64, exception: false)
        driver.changed
      end
    rescue IOError
      nil
    end

    # A turn while stopping: the sessions are told, and a connection whose
    # session the block never had is closed at once; once the sessions are
    # all over, or out of time, those left closed with the `error_code`
    # `stop` was given, the driver stops.
    private def stopping(now)
      timeout, error_code = @stop || return
      unless @stop_deadline
        @stop_deadline = now + timeout
        @sessions.each do |session|
          session.stopping!
          session.connection.close(error_code:, application: true, now:) unless @started.key?(session)
        end
      end
      deadline = @stop_deadline
      return unless @sessions.empty? || (deadline && now >= deadline)
      @sessions.each { |session| session.connection.close(error_code:, application: true, now:) }
      driver!.flush
      driver!.stop
    end

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
