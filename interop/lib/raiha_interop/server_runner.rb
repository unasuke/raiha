# frozen_string_literal: true

require "fileutils"
require "openssl"
require "securerandom"
require "socket"
require "raiha/server"
require "raiha/http3/server"
require "raiha/tls/config"

require_relative "testcases"

module RaihaInterop
  class ServerRunner
    DEFAULT_BIND_HOST = "0.0.0.0"
    DEFAULT_BIND_PORT = 443
    SELECT_TIMEOUT = 0.05

    def initialize(env:, testcase:, logger:)
      @env = env
      @testcase = testcase
      @logger = logger
      @http3_servers = {} #: Hash[Object, Raiha::HTTP3::Server]
      @control_setup = {} #: Hash[Object, bool]
      @served_streams = {} #: Hash[Object, Hash[Integer, bool]]
    end

    def run
      tls_config = build_tls_config
      server = Raiha::Server.new(
        tls_config: tls_config,
        alpn_protocols: alpn_protocols_for(@testcase),
        stateless_reset_key: @env["STATELESS_RESET_KEY"] || SecureRandom.random_bytes(32),
        retry_key: Testcases.requires_retry?(@testcase) ? (@env["RETRY_KEY"] || SecureRandom.random_bytes(32)) : nil,
        require_retry: Testcases.requires_retry?(@testcase)
      )

      host = @env["BIND_HOST"] || DEFAULT_BIND_HOST
      port = (@env["BIND_PORT"] || DEFAULT_BIND_PORT).to_i
      server.listen(host, port)
      socket = server.instance_variable_get(:@socket)
      log("listening on #{host}:#{port} testcase=#{@testcase}")

      install_signal_handlers
      open_connections = [] #: Array[Raiha::Connection]

      loop do
        break if @stop

        readable, = IO.select([socket], nil, nil, SELECT_TIMEOUT)
        if readable
          data, raw_addr = socket.recvfrom(65535)
          # UDPSocket#recvfrom yields [family, port, hostname, ip].
          # Reduce that to [ip, port] so Connection#peer_address (which
          # stores whatever we pass in) round-trips into a usable
          # sendto target downstream.
          peer_address = [raw_addr[3], raw_addr[1]]
          response = server.handle_packet(data, peer_address)
          socket.send(response, 0, peer_address[0], peer_address[1]) if response
        end

        loop do
          new_connection = server.accept_nonblock
          break unless new_connection
          attach_qlog(new_connection)
          open_connections << new_connection
        end

        now = Time.now
        open_connections.each do |connection|
          serve_http3(connection) if Testcases.requires_http3?(@testcase)
          connection.tick(now: now)
          connection.get_packets_to_send.each do |datagram|
            peer = connection.peer_address
            next unless peer
            socket.send(datagram, 0, peer[0], peer[1])
          end
        end
      end

      0
    rescue StandardError => error
      log("server error: #{error.class}: #{error.message}")
      log(error.backtrace.first(8).join("\n")) if error.backtrace
      1
    end

    private def install_signal_handlers
      [:INT, :TERM].each { |sig| Signal.trap(sig) { @stop = true } }
    end

    private def serve_http3(connection)
      return unless connection.handshake_complete?

      http3 = (@http3_servers[connection.object_id] ||= Raiha::HTTP3::Server.new(connection: connection))
      served = (@served_streams[connection.object_id] ||= {})

      unless @control_setup[connection.object_id]
        http3.setup_control_stream
        @control_setup[connection.object_id] = true
      end

      connection.streams.each_stream do |stream|
        next unless stream.stream_id.bidirectional? && stream.stream_id.client_initiated?
        next unless stream.fin_received?
        next if served[stream.stream_id.value]

        request = http3.receive_request(stream)
        root = @env["WWW"] || "/www"
        http3.serve_static(stream, request, root: root)
        served[stream.stream_id.value] = true
      end
    end

    private def attach_qlog(connection)
      qlog_dir = @env["QLOGDIR"]
      return if qlog_dir.nil? || qlog_dir.empty?

      FileUtils.mkdir_p(qlog_dir)
      cid = connection.src_connection_id.serialize.unpack1("H*")
      connection.enable_qlog(output: File.join(qlog_dir, "#{cid}.qlog"))
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
      Testcases.requires_http3?(testcase) ? ["h3"] : nil
    end

    private def log(message)
      @logger.puts("[raiha-interop server] #{message}")
    end
  end
end
