# frozen_string_literal: true

require "securerandom"

module Raiha::Runtime
  module Threaded
    # The server of the runtime on threads, as the Server of fibers is: an
    # Endpoint on a UDP socket of its own that takes clients up to
    # `max_connections` at a time, refusing more with CONNECTION_REFUSED,
    # and gives the block of `run` the Session of each connection once its
    # handshake completes, each in a thread of its own ("raiha-conn"). No
    # Fiber scheduler is needed. The arguments are those of the Server of
    # fibers, without `worker:`, as there are no Workers of threads, and
    # with `max_threads:`.
    #
    # A connection's handler counts toward `max_connections` until its
    # thread ends, though its connection has closed: a handler held up in
    # a library that blocks keeps its place, so that no more of them run
    # than `max_connections`. The threads of the streams of `each_stream`
    # and of the requests of HTTP/3, the application's besides, are
    # `max_threads` at most; one more waits for a place. So the threads
    # the server starts for the application are `max_connections +
    # max_threads` at most, and those of the driver, its readers and its
    # runner, and the one that waits for `stop` ("raiha-wake") besides.
    #
    # When the block is over, what the streams sent is let be acknowledged,
    # until three PTOs go with no more of it acknowledged, and the
    # connection closes with the application's
    # error 0; when it raises, the connection closes with INTERNAL_ERROR,
    # and the exception goes on, for its thread to report. Other
    # connections are not touched.
    #
    # `stop` asks the server to stop, from a signal handler as well, as the
    # Server of fibers has it. Once the driver has stopped, `run` waits for
    # the threads it started to end, until the time `stop` gave the
    # sessions is out, or STOP_TIMEOUT from when `run` was left by an
    # exception; those still running, held up in a library say, are left
    # to run, and `run` returns all the same. Their connections have
    # closed, and what they call of them raises QUIC::ClosedError.
    #
    # With `qlog_dir`, each connection has a qlog there, as the Server of
    # fibers has it, written outside the core lock.
    class Server
      MAX_CONNECTIONS = 64
      MAX_THREADS = 256
      STOP_TIMEOUT = Raiha::Runtime::Server::STOP_TIMEOUT

      def initialize(config:, tls_config:, keyring:, host: nil, port: nil, max_connections: MAX_CONNECTIONS, max_unvalidated: max_connections / 2,
        max_threads: MAX_THREADS, qlog_dir: nil, anti_replay: nil, app_early_data_context: "".b, stop_error_code: 0)
        unless max_unvalidated.is_a?(Integer) && (0..max_connections).cover?(max_unvalidated)
          raise ArgumentError, "max_unvalidated #{max_unvalidated.inspect} is not 0 to max_connections (#{max_connections})"
        end
        @threads = Threads.new(max_threads)
        @handlers = Threads.new(max_connections)
        @stop_error_code = stop_error_code
        @config = UDP.ecn(UDP.pmtud(UDP.batching(config)))
        @tls_config = tls_config
        @keyring = keyring
        @anti_replay = anti_replay || Raiha::TLS::AntiReplay::Memory.new(now: Time.now)
        @app_early_data_context = app_early_data_context
        @host = host || "::"
        @port = port || 443
        @max_connections = max_connections
        @max_unvalidated = max_unvalidated
        @admitted = [] #: Array[Raiha::QUIC::Endpoint::Handle]
        @qlog = qlog_dir && Qlog.new(qlog_dir, budget: Budget.current)
        # Who writes the qlog files: the runner after its turn, and whoever
        # stops the driver.
        @tracing = Thread::Mutex.new
        @traces = {} #: Hash[Session, Qlog::Pending]
        @traces.compare_by_identity
        @sessions = [] #: Array[Session]
        @started = {} #: Hash[Session, true]
        @started.compare_by_identity
        @handler = nil #: ^(Session) -> void | nil
        @driver = nil #: Driver?
        @done = nil #: MonitorMixin::ConditionVariable?
        @udp = nil #: UDP?
        @stop = nil #: [Float | Integer, Integer]?
        @stop_deadline = nil #: Float?
        @wake = nil #: IO?
      end

      # Binds the socket and serves until stopped, giving the block each
      # Session; raises what failed in the driver, if anything did.
      def run(&handler)
        @handler = handler
        udp = @udp = UDP.bind(@host, @port)
        others = preferred_sockets(udp)
        endpoint = Raiha::QUIC::Endpoint.server(config: @config, random: SecureRandom, time: Time.now, now: Driver.clock,
          connection_ids: Raiha::QUIC::RandomConnectionIDs.new(SecureRandom))
        driver = @driver = Driver.new(endpoint, udp, self, others:)
        done = @done = driver.new_cond
        reader, @wake = IO.pipe
        driver.start
        waker = Thread.new { wake_on(reader, driver) }.tap { |thread| thread.name = "raiha-wake" }
        driver.synchronize { done.wait until driver.stopped? }
        failure = driver.failure and raise failure
        nil
      ensure
        # Left by an exception as well, Interrupt say.
        @driver&.stop
        @driver&.join
        reader&.close
        @wake&.close
        waker&.join
        deadline = @stop_deadline || Driver.clock + STOP_TIMEOUT
        @handlers.join(deadline)
        @threads.join(deadline)
      end

      # [address, port] the socket is bound to, once `run` has bound it.
      def local_address = @udp&.local_address

      # Takes the connections to come with `tls_config` and `keyring`; those
      # already taken keep theirs.
      def reconfigure(tls_config:, keyring:)
        configure = lambda do
          @tls_config = tls_config
          @keyring = keyring
        end
        (driver = @driver) ? driver.synchronize(&configure) : configure.call
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
        nil
      end

      # The driver's owner, under the core lock: a new connection is taken
      # while there is room for it, a handler that has not ended taking room
      # as its connection does.
      def route(route, now)
        endpoint = @driver&.endpoint or return
        case route
        when Raiha::QUIC::Route::Incoming
          full = !@stop.nil? || @sessions.count { |session| !@started.key?(session) } + @handlers.taken >= @max_connections
          case Admission.decide(route, full:, max_unvalidated: @max_unvalidated) { unvalidated(now) }
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
          session = Session.new(connection, driver!, role: :server, threads: @threads, tracer:)
          @sessions << session
          @traces[session] = pending if pending
        end
      end

      # The driver's turn, under the core lock: each Session's, a handler for
      # each whose handshake has completed, and the sessions of connections
      # over let go.
      def turn(now)
        @admitted.reject! { |handle| handle.expired?(now) || handle.failed? }
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
      end

      def next_timeout = @stop_deadline

      def stopped(failure)
        @sessions.each { |session| session.abort(failure) }
        @traces.each_value(&:over!)
      ensure
        @done&.broadcast
      end

      # Writes what the traces have taken to their files, outside the core
      # lock, one writer at a time.
      def flush_traces
        qlog = @qlog or return
        driver = @driver or return
        @tracing.synchronize do
          taken = driver.synchronize { qlog.take }
          done = qlog.put(taken)
          driver.synchronize { qlog.retire(done) }
        end
      end

      private def unvalidated(now) = Admission.unvalidated(@admitted, @sessions.map(&:connection), now)

      private def driver! = @driver || raise(Error::Usage, "the server is not running")

      # A socket bound to "0.0.0.0" on the port of `udp` where `udp` is bound
      # to "::" and takes no IPv4 (OpenBSD), and one bound to each preferred
      # address that none bound so far sends from; none is left open when
      # one cannot be bound, nor `udp`.
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

      # A turn while stopping, as the Server of fibers has it; the last
      # datagrams go, and the sockets close, once the turn is over.
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

      # The handler of `session` in a thread of its own, counted until it
      # ends. One that cannot be started closes the connection with
      # INTERNAL_ERROR, as one that raises does.
      private def start(session)
        @started[session] = true
        handler = @handler or return
        driver = driver!
        @handlers.count
        @handlers.start("raiha-conn") do
          raise Error::Usage, "the core lock of the driver is held where the application runs" if driver.mon_owned?
          handler.call(session)
          session.close_when_acknowledged
        rescue Raiha::QUIC::ClosedError
          nil
        rescue StandardError
          internal_error(session)
          raise
        end
      rescue ThreadError
        internal_error(session)
      end

      private def internal_error(session)
        session.connection.close(error_code: Raiha::QUIC::ErrorCode::INTERNAL_ERROR, application: false, now: Driver.clock)
        session.changed
      end
    end
  end
end
