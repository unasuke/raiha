# frozen_string_literal: true

require "socket"
require "securerandom"

module Raiha::Next::Runtime
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
  # connection closes with the application's error 0. The closing period
  # is not waited out: the CONNECTION_CLOSE goes, and the socket closes.
  class Client
    CONNECT_TIMEOUT = 5.0

    def self.connect(host, port, config:, tls_config:, keyring:, server_name: host, connect_timeout: CONNECT_TIMEOUT, &)
      new(config:, tls_config:, keyring:, connect_timeout:).connect(host, port, server_name:, &)
    end

    def initialize(config:, tls_config:, keyring:, connect_timeout: CONNECT_TIMEOUT)
      @config = config
      @tls_config = tls_config
      @keyring = keyring
      @connect_timeout = connect_timeout
      @session = nil #: Session?
      @deadline = nil #: Float?
    end

    def connect(host, port, server_name: host)
      raise Error::Usage, "the runtime waits through a Fiber scheduler; this thread has none" unless Fiber.scheduler
      errors = [] #: Array[[UDP::address | String, StandardError]]
      addresses = begin
        resolve(host, port)
      rescue SocketError => error
        raise ConnectError.new(host, port, [[host, error]])
      end
      addresses.each do |address|
        driver, session = attempt(address, server_name)
        begin
          session.wait_handshake
        rescue Raiha::Next::QUIC::ClosedError => error
          driver.stop
          errors << [address, error]
          next
        end
        begin
          return yield session
        ensure
          finish(driver, session)
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
      deadline = @deadline or return
      return @deadline = nil if session.connection.handshake_complete?
      return if now < deadline
      @deadline = nil
      session.connection.close(error_code: Raiha::Next::QUIC::ErrorCode::NO_ERROR, reason: "no handshake in #{@connect_timeout} seconds",
        application: false, now:)
    end

    def next_timeout = @deadline

    def stopped(failure)
      @session&.abort(failure)
    end

    # Closes the connection once what was sent is acknowledged or three PTOs
    # have gone, and stops the driver.
    private def finish(driver, session)
      unless session.closed?
        session.close_when_acknowledged
        driver.flush
      end
    rescue Raiha::Next::QUIC::ClosedError
      nil
    ensure
      driver.stop
    end

    # [address, port] of `host` for UDP, each once.
    private def resolve(host, port)
      Addrinfo.getaddrinfo(host, port, nil, :DGRAM).map do |info|
        [info.ip_address, info.ip_port] #: UDP::address
      end.uniq
    end

    # A connection to `address` on a socket of its own, its handshake under
    # way: [driver, session].
    private def attempt(address, server_name)
      udp = UDP.bind(address[0].include?(":") ? "::" : "0.0.0.0", 0)
      endpoint = Raiha::Next::QUIC::Endpoint.client(config: @config, random: SecureRandom, time: Time.now, now: Driver.clock)
      driver = Driver.new(endpoint, udp, self)
      connection = endpoint.connect(tls_config: @tls_config, keyring: @keyring, server_name:, remote: address, now: Driver.clock)
      session = @session = Session.new(connection, driver, role: :client)
      @deadline = Driver.clock + @connect_timeout
      driver.start
      [driver, session]
    end
  end
end
