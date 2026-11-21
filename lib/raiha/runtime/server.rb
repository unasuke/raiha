# frozen_string_literal: true

require "securerandom"

module Raiha::Runtime
  # The server of the runtime: an Endpoint on a UDP socket of its own that
  # takes every client up to `max_connections` at a time, refusing more
  # with CONNECTION_REFUSED, and gives the block of `run` the Session of
  # each connection once its handshake completes, in a fiber of its own.
  # Once `max_unvalidated` connections, half of `max_connections` unless
  # told, have addresses not validated, a client whose address no token
  # has shown is sent a Retry first, so that Initials from addresses
  # spoofed by the thousand cannot take the rest: those are the offers
  # admitted and not yet taken, and the connections whose address the
  # handshake has not validated yet, as one from a spoofed address never
  # is. With 0, every such client is sent one.
  #
  # When the block is over, what the streams sent is let be acknowledged,
  # until three PTOs go with no more of it acknowledged, and the connection
  # closes with the application's error 0;
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
  # (UDP.pmtud), and no ECN on IPv4 where the OS cannot mark it (UDP.ecn).
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
  #
  # Given a `worker`, the server is one of the workers of Workers: it binds
  # nothing and reads the sockets bound for it, its first, one of
  # "0.0.0.0" where the first is "::" taking no IPv4, and those of the
  # preferred addresses; it issues connection IDs that tell its worker
  # (QUIC::WorkerConnectionIDs), fills the keys a `config` leaves out with
  # those every worker shares, records 0-RTT in the worker's shared
  # `anti_replay` unless given one, and its driver hands on to the other
  # workers what came for their connections. What Workers asks through the
  # worker's control port, to stop or to take other TLS settings, is done
  # in the driver's turn, a stop with `stop_error_code` for the connections
  # left. A `host` or `port` beside it is ArgumentError.
  class Server
    MAX_CONNECTIONS = 1024
    STOP_TIMEOUT = 30

    def initialize(config:, tls_config:, keyring:, host: nil, port: nil, max_connections: MAX_CONNECTIONS, max_unvalidated: max_connections / 2,
      qlog_dir: nil, anti_replay: nil, app_early_data_context: "".b, worker: nil, stop_error_code: 0)
      raise ArgumentError, "a worker's server binds no host or port of its own" if worker && (host || port)
      unless max_unvalidated.is_a?(Integer) && (0..max_connections).cover?(max_unvalidated)
        raise ArgumentError, "max_unvalidated #{max_unvalidated.inspect} is not 0 to max_connections (#{max_connections})"
      end
      @worker = worker
      @stop_error_code = stop_error_code
      config = config.with(retry_token_key: config.retry_token_key || worker.config.retry_token_key,
        stateless_reset_key: config.stateless_reset_key || worker.config.stateless_reset_key) if worker
      @config = UDP.ecn(UDP.pmtud(UDP.batching(config)))
      @tls_config = tls_config
      @keyring = keyring
      @anti_replay = anti_replay || worker&.anti_replay || Raiha::TLS::AntiReplay::Memory.new(now: Time.now)
      @app_early_data_context = app_early_data_context
      @host = host || "::"
      @port = port || 443
      # What the worker's control port asked, for the driver's turn, and
      # what failed in the thread that waits on it.
      @controls = Thread::Queue.new
      @worker_failure = nil #: StandardError?
      @max_connections = max_connections
      @max_unvalidated = max_unvalidated
      # The offers admitted whose ClientHello is not whole yet and whose
      # client's address is not validated, let go each turn once over.
      @admitted = [] #: Array[Raiha::QUIC::Endpoint::Handle]
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
      udp, others, connection_ids = sockets
      endpoint = Raiha::QUIC::Endpoint.server(config: @config, random: SecureRandom, time: Time.now, now: Driver.clock, connection_ids:)
      # Known before it starts, so that leaving `run` while it starts stops
      # it too.
      driver = @driver = Driver.new(endpoint, udp, self, others:, worker: @worker)
      driver.start
      @worker&.listen(changed: -> { driver.changed }, failed: ->(error) { (@worker_failure = error) && driver.changed }) do |message|
        @controls << message
        driver.changed
      end
      reader, @wake = IO.pipe
      Fiber.schedule { wake_on(reader, driver) }
      @lock.synchronize { @stopped.wait(@lock) until driver.stopped? }
      failure = driver.failure and raise failure
      nil
    ensure
      # Left by an exception, or by the task running it being stopped.
      @driver&.stop
      @worker&.close
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
      when Raiha::QUIC::Route::Incoming
        case Admission.decide(route, full: !@stop.nil? || @sessions.size >= @max_connections, max_unvalidated: @max_unvalidated) { unvalidated(now) }
        when :refuse then return endpoint.refuse(route.handle)
        when :retry then return endpoint.retry(route.handle, now:)
        end
        hello = endpoint.admit(route.handle, now:)
        return route(hello, now) if hello
        @admitted << route.handle unless route.address_validated
      when Raiha::QUIC::Route::ClientHello
        @admitted.delete(route.handle)
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
      failure = @worker_failure and raise failure
      @admitted.reject! { |handle| handle.expired?(now) || handle.failed? }
      while (message = @controls.pop(timeout: 0))
        control(message)
      end
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

    # How many of the offers admitted and the connections taken have
    # addresses not validated.
    private def unvalidated(now) = Admission.unvalidated(@admitted, @sessions.map(&:connection), now)

    def stopped(failure)
      @sessions.each { |session| session.abort(failure) }
      @traces.each_value(&:over!)
      @qlog&.flush
    ensure
      @lock.synchronize { @stopped.broadcast }
    end

    private def driver! = @driver || raise(Error::Usage, "the server is not running")

    # The socket, those besides it, and the connection IDs to issue: of the
    # worker, or bound here.
    private def sockets
      if (worker = @worker)
        first, *others = worker.sockets.map { |socket| UDP.new(socket) }
        ids = Raiha::QUIC::WorkerConnectionIDs.new(SecureRandom, worker_id: worker.id, worker_count: worker.count,
          key: @config.stateless_reset_key || raise(Error::Usage, "a worker's Config has no stateless_reset_key"))
        udp = first or raise Error::Usage, "the worker has no socket"
        @udp = udp
        return [udp, others, ids]
      end
      udp = @udp = UDP.bind(@host, @port)
      [udp, preferred_sockets(udp), Raiha::QUIC::RandomConnectionIDs.new(SecureRandom)]
    end

    # What Workers asked through the worker's control port.
    private def control(message)
      case message
      in [:stop, timeout] then stop(timeout:, error_code: @stop_error_code)
      in [:reconfigure, tls_config, identities] then reconfigure(tls_config:, keyring: Raiha::TLS::Keyring.server(config: tls_config, identities:))
      else nil
      end
    end

    # A socket bound to "0.0.0.0" on the port of `udp` where `udp` is bound
    # to "::" and takes no IPv4 (OpenBSD), and one bound to each preferred
    # address that none bound so far sends from; none is left open when one
    # cannot be bound, nor `udp`. "0.0.0.0" comes first, as a specific
    # address of IPv4 bound on the same port would keep it from binding.
    private def preferred_sockets(udp)
      others = [] #: Array[UDP]
      bound = udp.to_io.local_address
      addresses = @config.preferred_address&.values || [] #: Array[UDP::address]
      if bound.ipv6? && bound.ipv6_unspecified? && !udp.takes_ipv4?
        addresses = [["0.0.0.0", bound.ip_port], *addresses] #: Array[UDP::address]
      end
      addresses.each do |host, port|
        others << UDP.bind(host, port) unless [udp, *others].any? { |socket| socket.sends_from?([host, port]) }
      rescue SystemCallError
        [udp, *others].each(&:close)
        raise
      end
      others
    end

    # A ticket is sealed with the key of the epoch it is issued in, and keys
    # of epochs long gone stop opening any.
    private def advance_ticket_keys
      keyring = Admission.advance_ticket_keys(@tls_config, @keyring, Time.now) or return
      @keyring = keyring
      @tls_config = keyring.config
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
      rescue Raiha::QUIC::ClosedError
        nil
      rescue StandardError
        session.connection.close(error_code: Raiha::QUIC::ErrorCode::INTERNAL_ERROR, application: false, now: Driver.clock)
        driver!.changed
        raise
      end
    end
  end
end
