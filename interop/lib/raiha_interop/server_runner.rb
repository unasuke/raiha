# frozen_string_literal: true

require "openssl"
require "socket"
require "raiha/server"
require "raiha/tls/config"

module RaihaInterop
  class ServerRunner
    DEFAULT_BIND_HOST = "0.0.0.0"
    DEFAULT_BIND_PORT = 443
    SELECT_TIMEOUT = 0.05

    def initialize(env:, testcase:, logger:)
      @env = env
      @testcase = testcase
      @logger = logger
    end

    def run
      tls_config = build_tls_config
      server = Raiha::Server.new(
        tls_config: tls_config,
        alpn_protocols: alpn_protocols_for(@testcase),
        stateless_reset_key: @env["STATELESS_RESET_KEY"] || SecureRandom.random_bytes(32),
        retry_key: retry_required? ? (@env["RETRY_KEY"] || SecureRandom.random_bytes(32)) : nil,
        require_retry: retry_required?
      )

      host = @env["BIND_HOST"] || DEFAULT_BIND_HOST
      port = (@env["BIND_PORT"] || DEFAULT_BIND_PORT).to_i
      server.listen(host, port)
      socket = server.instance_variable_get(:@socket)
      log("listening on #{host}:#{port} testcase=#{@testcase}")

      install_signal_handlers
      loop do
        break if @stop

        readable, = IO.select([socket], nil, nil, SELECT_TIMEOUT)
        if readable
          data, addr = socket.recvfrom(65535)
          response = server.handle_packet(data, addr)
          socket.send(response, 0, addr[3], addr[1]) if response
        end

        drain_connections(server, socket)
      end

      0
    rescue StandardError => error
      log("server error: #{error.class}: #{error.message}")
      1
    end

    private def install_signal_handlers
      [:INT, :TERM].each { |sig| Signal.trap(sig) { @stop = true } }
    end

    private def drain_connections(server, socket)
      loop do
        connection = server.accept_nonblock
        break unless connection

        @open_connections ||= []
        @open_connections << connection
      end

      now = Time.now
      (@open_connections ||= []).each do |connection|
        connection.tick(now: now)
        connection.get_packets_to_send.each do |datagram|
          peer = connection.peer_address
          next unless peer

          host, port = peer
          socket.send(datagram, 0, host, port)
        end
      end
    end

    private def build_tls_config
      certs_dir = @env["CERTS"] || "/certs"
      cert_path = File.join(certs_dir, "cert.pem")
      key_path = File.join(certs_dir, "priv.key")
      raise "missing #{cert_path}" unless File.exist?(cert_path)
      raise "missing #{key_path}" unless File.exist?(key_path)

      tls_config = Raiha::TLS::Config.server_default
      tls_config.server_certificate = OpenSSL::X509::Certificate.new(File.read(cert_path))
      tls_config.server_private_key = OpenSSL::PKey.read(File.read(key_path))
      tls_config
    end

    private def alpn_protocols_for(testcase)
      case testcase
      when "http3", "transfer" then ["h3"]
      else nil
      end
    end

    private def retry_required?
      @testcase == "retry"
    end

    private def log(message)
      @logger.puts("[raiha-interop server] #{message}")
    end
  end
end
