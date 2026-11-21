# frozen_string_literal: true

require "securerandom"
require_relative "../../http3/session"

module Raiha::Runtime
  module Threaded
    # The client of the runtime on threads, as the Client of fibers is:
    # Client.connect finds the addresses of a host and connects to each in
    # turn, a socket of its own for each, until one completes its handshake
    # within `connect_timeout` seconds, then gives the block a Session of
    # the connection, in the thread that called it; no Fiber scheduler is
    # needed. The arguments are those of the Client of fibers, with
    # `max_threads:`: the threads of the streams of `each_stream`, which
    # wait for a place while that many run. The block's value is returned.
    #
    # Once the block is over, what the streams sent is let be acknowledged,
    # until three PTOs go with no more of it acknowledged, the connection
    # closes, and the threads of its
    # streams are waited for, Server::STOP_TIMEOUT at most; those still
    # running are left to. An attempt that fails has its driver's threads
    # ended before the next address is tried.
    class Client
      CONNECT_TIMEOUT = Raiha::Runtime::Client::CONNECT_TIMEOUT
      MAX_THREADS = 64

      def self.connect(host, port, config:, tls_config:, keyring:, server_name: host, connect_timeout: CONNECT_TIMEOUT, qlog_dir: nil,
        session: nil, token: nil, early_data: false, max_threads: MAX_THREADS, &)
        new(config:, tls_config:, keyring:, connect_timeout:, qlog_dir:, max_threads:).connect(host, port, server_name:, session:, token:,
          early_data:, &)
      end

      def initialize(config:, tls_config:, keyring:, connect_timeout: CONNECT_TIMEOUT, qlog_dir: nil, max_threads: MAX_THREADS)
        @threads = Threads.new(max_threads)
        @config = UDP.ecn(UDP.pmtud(UDP.batching(config)))
        @tls_config = tls_config
        @keyring = keyring
        @connect_timeout = connect_timeout
        @session = nil #: Session?
        @driver = nil #: Driver?
        @deadline = nil #: Float?
        @qlog = qlog_dir && Qlog.new(qlog_dir, budget: Budget.current)
        @tracing = Thread::Mutex.new
        @trace = nil #: Qlog::Pending?
      end

      def connect(host, port, server_name: host, session: nil, token: nil, early_data: false)
        errors = [] #: Array[[UDP::address | String, StandardError]]
        addresses = begin
          resolve(host, port)
        rescue SocketError => error
          raise ConnectError.new(host, port, [[host, error]])
        end
        addresses.each do |address|
          begin
            driver, opened = attempt(address, server_name, session:, token:, early_data:)
          rescue SystemCallError => error
            errors << [address, error]
            next
          end
          session = token = nil
          connected = false
          begin
            driver.start
            opened.wait_ready
            connected = true
          rescue Raiha::QUIC::ClosedError => error
            errors << [address, error]
            next
          ensure
            # However the attempt is left, Interrupt included.
            unless connected
              driver.stop
              driver.join
            end
          end
          begin
            raise Error::Usage, "the core lock of the driver is held where the application runs" if driver.mon_owned?
            return yield opened
          ensure
            finish(driver, opened)
          end
        end
        raise ConnectError.new(host, port, errors)
      end

      # The driver's owner: a client has no Route to take.
      def route(route, now) = nil

      # The driver's turn, under the core lock: the Session's, and the end of
      # the time to connect.
      def turn(now)
        session = @session or return
        session.turn
        deadline = @deadline or return
        connection = session.connection
        return @deadline = nil if connection.handshake_complete?
        return if now < deadline
        @deadline = nil
        connection.close(error_code: Raiha::QUIC::ErrorCode::NO_ERROR, reason: "no handshake in #{@connect_timeout} seconds",
          application: false, now:)
      end

      def next_timeout = @deadline

      def stopped(failure)
        @session&.abort(failure)
        @trace&.over!
      end

      # Writes what the trace has taken to its file, outside the core lock,
      # one writer at a time.
      def flush_traces
        qlog = @qlog or return
        driver = @driver or return
        @tracing.synchronize do
          taken = driver.synchronize { qlog.take }
          done = qlog.put(taken)
          driver.synchronize { qlog.retire(done) }
        end
      end

      # Closes the connection once what was sent is acknowledged, or three
      # PTOs have gone with no more of it acknowledged, sends the
      # CONNECTION_CLOSE, of a close in the block
      # as well, stops the driver, and waits for the threads of the
      # streams.
      private def finish(driver, session)
        session.close_when_acknowledged unless session.closed?
        driver.flush
      rescue Raiha::QUIC::ClosedError
        nil
      ensure
        driver.stop
        driver.join
        @threads.join(Driver.clock + Server::STOP_TIMEOUT)
      end

      # The addresses to try, as Addresses.resolve finds them.
      private def resolve(host, port) = Addresses.resolve(host, port)

      # A connection to `address` on a socket of its own, its handshake to
      # begin once the driver starts: [driver, session].
      private def attempt(address, server_name, session:, token:, early_data:)
        made = false
        udp, config = Addresses.bind(address, @config)
        endpoint = Raiha::QUIC::Endpoint.client(config:, random: SecureRandom, time: Time.now, now: Driver.clock)
        driver = @driver = Driver.new(endpoint, udp, self)
        tracer, @trace = @qlog&.trace(:client, Time.now.utc.strftime("%Y%m%dT%H%M%S.%6N"), tls_config: @tls_config)
        quic = session.is_a?(Raiha::HTTP3::Session) ? session.quic : session
        connection = endpoint.connect(tls_config: @tls_config, keyring: @keyring, server_name:, remote: address, now: Driver.clock, tracer:,
          session: quic, token:, early_data:)
        opened = @session = Session.new(connection, driver, role: :client, threads: @threads, tracer:, server_name:, resumed: session)
        @deadline = Driver.clock + @connect_timeout
        made = true
        [driver, opened] #: [Driver, Session]
      ensure
        udp&.close unless made
      end
    end
  end
end
