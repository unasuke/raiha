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
  #
  # With `qlog_dir`, each connection has a qlog there, named by the
  # Destination Connection ID the client first chose.
  #
  # A `config` without max_transmit_size takes UDP::MAX_TRANSMIT, as the
  # socket sends the datagrams of a Transmit with GSO (UDP.batching), and
  # enable_pmtud false where the socket cannot keep IP from fragmenting
  # (UDP.pmtud).
  #
  # A `config` with a preferred_address has a socket bound to each of its
  # addresses as well, unless the first socket takes what comes there
  # already, bound to any address on its port; `run` raises the error of
  # one it cannot bind, so that no client is offered an address the server
  # does not listen at.
  #
  # When the ticket keys of `tls_config` are a TicketKeys.ratchet, the
  # server builds them again once their epoch is over, before the next
  # connection it takes, with a Keyring to match. Keys of another kind are
  # the application's to turn over, with `reconfigure`.
  #
  # The 0-RTT a `tls_config` takes is recorded in `anti_replay`, so that
  # the server takes each ClientHello's at most once; without one, the
  # server has a TLS::AntiReplay::Memory of its own, which takes none for
  # its first seconds (RFC 9846 "Client Hello Recording"). Servers of
  # other processes that open the same tickets record apart, so each may
  # take a ClientHello's 0-RTT once. `app_early_data_context` is what of
  # the application its 0-RTT relies on, so that the 0-RTT of a ticket
  # issued with other settings is rejected (Endpoint#accept).
  class Server
    MAX_CONNECTIONS = 1024
    STOP_TIMEOUT = 30

    def initialize(config:, tls_config:, keyring:, host: "::", port: 443, max_connections: MAX_CONNECTIONS, qlog_dir: nil,
      anti_replay: nil, app_early_data_context: "".b)
      @config = UDP.pmtud(UDP.batching(config))
      @tls_config = tls_config
      @keyring = keyring
      @anti_replay = anti_replay || Raiha::Next::TLS::AntiReplay::Memory.new(now: Time.now)
      @app_early_data_context = app_early_data_context
      @host = host
      @port = port
      @max_connections = max_connections
      @qlog = qlog_dir && Qlog.new(qlog_dir)
      @traces = {} #: Hash[Session, Qlog::Pending]
      @traces.compare_by_identity
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
      others = preferred_sockets(udp)
      endpoint = Raiha::Next::QUIC::Endpoint.server(config: @config, random: SecureRandom, time: Time.now, now: Driver.clock)
      # Known before it starts, so that leaving `run` while it starts stops
      # it too.
      driver = @driver = Driver.new(endpoint, udp, self, others:)
      driver.start
      reader, @wake = IO.pipe
      Fiber.schedule { wake_on(reader, driver) }
      @lock.synchronize { @stopped.wait(@lock) until driver.stopped? }
      failure = driver.failure and raise failure
      nil
    ensure
      # Left by an exception, or by the task running it being stopped.
      @driver&.stop
      reader&.close
      @wake&.close
    end

    # [address, port] the socket is bound to, once `run` has bound it.
    def local_address = @udp&.local_address

    # Takes the connections to come with `tls_config` and `keyring`, a new
    # certificate, say; those already taken keep theirs. The QUIC Config
    # stays: its keys and the length of its connection IDs are what the
    # Endpoint was made with.
    def reconfigure(tls_config:, keyring:)
      @tls_config = tls_config
      @keyring = keyring
      nil
    end

    # Asks the server to stop, giving the sessions `timeout` seconds; the
    # first call is the one that counts. It takes no lock and writes to a
    # pipe without waiting, so a signal handler may call it.
    def stop(timeout: STOP_TIMEOUT, error_code: 0)
      @stop ||= [timeout, error_code]
      @wake&.write_nonblock(".", exception: false)
      nil
    rescue IOError, SystemCallError
      # `run` is returning and has closed the pipe, or the end it reads.
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
        advance_ticket_keys
        tracer, pending = @qlog&.trace(:server, route.handle.original_destination_connection_id.unpack1("H*"), tls_config: @tls_config)
        connection = endpoint.accept(route.handle, tls_config: @tls_config, keyring: @keyring, now:, tracer:, anti_replay: @anti_replay,
          app_early_data_context: @app_early_data_context)
        session = Session.new(connection, driver!, role: :server, tracer:)
        @sessions << session
        @traces[session] = pending if pending
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
      over.each do |session|
        @started.delete(session)
        @traces.delete(session)&.over!
      end
      @sessions -= over
      stopping(now) if @stop
      @qlog&.flush
    end

    def next_timeout = @stop_deadline

    def stopped(failure)
      @sessions.each { |session| session.abort(failure) }
      @traces.each_value(&:over!)
      @qlog&.flush
    ensure
      @lock.synchronize { @stopped.broadcast }
    end

    private def driver! = @driver || raise(Error::Usage, "the server is not running")

    # A socket bound to each preferred address that none bound so far
    # sends from; none is left open when one cannot be bound, nor `udp`.
    private def preferred_sockets(udp)
      others = [] #: Array[UDP]
      (@config.preferred_address&.values || []).each do |host, port|
        others << UDP.bind(host, port) unless [udp, *others].any? { |socket| socket.sends_from?([host, port]) }
      rescue SystemCallError
        [udp, *others].each(&:close)
        raise
      end
      others
    end

    # A ticket is sealed with the key of the epoch it is issued in, and keys
    # of epochs long gone stop opening any. A Keyring of another Config is
    # left for the handshake to refuse.
    private def advance_ticket_keys
      keys = @tls_config.ticket_keys or return
      at = keys.next_advance_at or return
      time = Time.now
      return if time < at || !@keyring.config.equal?(@tls_config)
      @keyring = @keyring.with_ticket_keys(keys.advance(now: time))
      @tls_config = @keyring.config
    end

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
          session.stopping!(@stop_deadline)
          session.connection.close(error_code:, application: true, now:) unless @started.key?(session)
        end
      end
      deadline = @stop_deadline
      return unless @sessions.empty? || (deadline && now >= deadline)
      @sessions.each { |session| session.expire(error_code:) }
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
