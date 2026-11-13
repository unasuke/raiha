# frozen_string_literal: true

require "socket"
require "securerandom"
require_relative "../http3/session"

module Raiha::Runtime
  # No address of a host took a connection. `errors` has, for each address
  # tried, [address, what failed]: the QUIC::ClosedError of a connection
  # that closed or ran out of time, or the error of a name that did not
  # resolve.
  class ConnectError < StandardError
    attr_reader :errors

    def initialize(host, port, errors)
      @errors = errors
      tried = errors.map { |address, error| "#{address.inspect}: #{error.message}" }
      super("could not connect to #{host}:#{port} (#{tried.join("; ")})")
    end
  end

  # The client of the runtime. Client.connect finds the addresses of a
  # host and connects to each in turn, a socket of its own for each, until
  # one completes its handshake within `connect_timeout` seconds, then gives
  # the block a Session of the connection. There is no discovery of HTTP/3
  # (Alt-Svc, HTTPS records) and no fallback to TCP: the host and port are
  # taken to speak QUIC. The block's value is returned.
  #
  # Once the block is over, what the streams sent is given three PTOs to be
  # acknowledged, so a response written last is not cut short, and the
  # connection closes with the application's error 0, or that of the
  # protocol attached to the Session: H3_NO_ERROR for HTTP/3. The closing
  # period is not waited out: the CONNECTION_CLOSE goes, and the socket
  # closes.
  #
  # With `qlog_dir`, each connection tried has a qlog there, named by the
  # time it began.
  #
  # A `config` without max_transmit_size takes UDP::MAX_TRANSMIT, as the
  # socket sends the datagrams of a Transmit with GSO (UDP.batching), and
  # enable_pmtud false where the socket cannot keep IP from fragmenting
  # (UDP.pmtud).
  #
  # Each socket is bound to "::", which sends to IPv4 too, so that a
  # connection can move to a server's preferred address of either family;
  # where IPv6 is off and it cannot be, to "0.0.0.0", and the connection
  # takes IPv4 addresses alone (Config#address_families). The address a
  # datagram goes from is the OS's to choose.
  #
  # With `session`, a ticket an earlier connection's Session#tickets gave,
  # the first connection tried resumes it, and with `token`, one of its
  # Session#tokens, its Initials carry it, so that the server need not
  # validate the address again. Each is for one connection, which those
  # tried after the first do not reuse (RFC 9846 "Client and Server
  # Tracking Prevention", RFC 9000 "Address Validation for Future
  # Connections"); once used, the application drops it. A ticket of HTTP3::Client#tickets, an
  # HTTP3::Session, resumes its QUIC::Session, and HTTP/3 keeps to its
  # SETTINGS while 0-RTT goes.
  #
  # With `early_data` true as well, and a ticket that allows it, the
  # connection sends what the block writes before its handshake completes,
  # in 0-RTT: the block is given the Session at once. A connection given to
  # the block is not tried at another address, as what it sent in 0-RTT is
  # not to be sent again unless the application says so (RFC 9846 "Replay
  # Attacks on 0-RTT"): one that fails raises QUIC::ClosedError in the
  # block. An attacker may replay 0-RTT, so only what is safe to repeat
  # goes before Session#wait_handshake.
  class Client
    CONNECT_TIMEOUT = 5.0

    def self.connect(host, port, config:, tls_config:, keyring:, server_name: host, connect_timeout: CONNECT_TIMEOUT, qlog_dir: nil,
      session: nil, token: nil, early_data: false, &)
      new(config:, tls_config:, keyring:, connect_timeout:, qlog_dir:).connect(host, port, server_name:, session:, token:, early_data:, &)
    end

    def initialize(config:, tls_config:, keyring:, connect_timeout: CONNECT_TIMEOUT, qlog_dir: nil)
      @config = UDP.pmtud(UDP.batching(config))
      @tls_config = tls_config
      @keyring = keyring
      @connect_timeout = connect_timeout
      @session = nil #: Session?
      @deadline = nil #: Float?
      @qlog = qlog_dir && Qlog.new(qlog_dir)
      @trace = nil #: Qlog::Pending?
    end

    def connect(host, port, server_name: host, session: nil, token: nil, early_data: false)
      raise Error::Usage, "the runtime waits through a Fiber scheduler; this thread has none" unless Fiber.scheduler
      errors = [] #: Array[[UDP::address | String, StandardError]]
      addresses = begin
        resolve(host, port)
      rescue SocketError => error
        raise ConnectError.new(host, port, [[host, error]])
      end
      addresses.each do |address|
        driver, opened = attempt(address, server_name, session:, token:, early_data:)
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
          # However the attempt is left, a task stopped included.
          driver.stop unless connected
        end
        begin
          return yield opened
        ensure
          finish(driver, opened)
        end
      end
      raise ConnectError.new(host, port, errors)
    end

    # The driver's owner: a client has no Route to take.
    def route(route, now) = nil

    # The driver's turn: the Session's, and the end of the time to connect.
    def turn(now)
      session = @session or return
      session.turn
      @qlog&.flush
      deadline = @deadline or return
      return @deadline = nil if session.connection.handshake_complete?
      return if now < deadline
      @deadline = nil
      session.connection.close(error_code: Raiha::QUIC::ErrorCode::NO_ERROR, reason: "no handshake in #{@connect_timeout} seconds",
        application: false, now:)
    end

    def next_timeout = @deadline

    def stopped(failure)
      @session&.abort(failure)
      @trace&.over!
      @qlog&.flush
    end

    # Closes the connection once what was sent is acknowledged or three PTOs
    # have gone, and stops the driver.
    private def finish(driver, session)
      unless session.closed?
        session.close_when_acknowledged
        driver.flush
      end
    rescue Raiha::QUIC::ClosedError
      nil
    ensure
      driver.stop
    end

    # A socket for a connection, and the Config for its addresses.
    private def bind
      [UDP.bind("::", 0), @config]
    rescue SystemCallError
      [UDP.bind("0.0.0.0", 0), @config.with(address_families: %i[ipv4])]
    end

    # [address, port] of `host` for UDP, each once.
    private def resolve(host, port)
      Addrinfo.getaddrinfo(host, port, nil, :DGRAM).map do |info|
        [info.ip_address, info.ip_port] #: UDP::address
      end.uniq
    end

    # A connection to `address` on a socket of its own, its handshake to
    # begin once the driver starts: [driver, session].
    private def attempt(address, server_name, session:, token:, early_data:)
      made = false
      udp, config = bind
      endpoint = Raiha::QUIC::Endpoint.client(config:, random: SecureRandom, time: Time.now, now: Driver.clock)
      driver = Driver.new(endpoint, udp, self)
      tracer, @trace = @qlog&.trace(:client, Time.now.utc.strftime("%Y%m%dT%H%M%S.%6N"), tls_config: @tls_config)
      quic = session.is_a?(Raiha::HTTP3::Session) ? session.quic : session
      connection = endpoint.connect(tls_config: @tls_config, keyring: @keyring, server_name:, remote: address, now: Driver.clock, tracer:,
        session: quic, token:, early_data:)
      opened = @session = Session.new(connection, driver, role: :client, tracer:, server_name:, resumed: session)
      @deadline = Driver.clock + @connect_timeout
      made = true
      [driver, opened] #: [Driver, Session]
    ensure
      # A connection that cannot be made, a Keyring for another Config say,
      # leaves no socket behind.
      udp&.close unless made
    end
  end
end
