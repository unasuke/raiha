# frozen_string_literal: true

require "socket"
require "uri"
require "raiha/connection"
require "raiha/quic/protocol/connection_id"

module RaihaInterop
  class ClientRunner
    SELECT_TIMEOUT = 0.05
    DEFAULT_HANDSHAKE_DEADLINE = 30 # seconds

    def initialize(env:, testcase:, logger:)
      @env = env
      @testcase = testcase
      @logger = logger
    end

    def run
      host, port = resolve_server
      requests = parse_requests(@env["REQUESTS"])
      authority = requests.first ? URI.parse(requests.first).host : host
      socket = build_socket(host, port)

      connection = Raiha::Connection.new(
        perspective: :client,
        src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
        dest_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
        server_name: authority,
        alpn_protocols: alpn_protocols_for(@testcase)
      )

      enable_observability(connection)
      connection.start_handshake
      flush(connection, socket)

      deadline = Time.now + DEFAULT_HANDSHAKE_DEADLINE
      until connection.handshake_complete?
        return 1 if Time.now > deadline

        readable, = IO.select([socket], nil, nil, SELECT_TIMEOUT)
        if readable
          data, _ = socket.recvfrom(65535)
          connection.handle_packet(data)
        end
        connection.tick
        flush(connection, socket)
      end

      log("handshake complete")
      connection.close
      flush(connection, socket)
      0
    rescue StandardError => error
      log("client error: #{error.class}: #{error.message}")
      1
    end

    private def resolve_server
      target = @env["WAITFORSERVER"] || @env["SERVER"]
      raise "WAITFORSERVER not set" unless target
      host, port = target.split(":")
      [host, (port || @env["PORT"] || 443).to_i]
    end

    private def parse_requests(raw)
      return [] if raw.nil? || raw.empty?
      raw.split(/[\s,]+/).reject(&:empty?)
    end

    private def build_socket(host, port)
      socket = UDPSocket.new
      socket.connect(host, port)
      socket
    end

    private def enable_observability(connection)
      qlog_dir = @env["QLOGDIR"]
      if qlog_dir && !qlog_dir.empty?
        Dir.mkdir(qlog_dir) unless Dir.exist?(qlog_dir)
        cid_hex = connection.src_connection_id.serialize.unpack1("H*")
        connection.enable_qlog(output: File.join(qlog_dir, "#{cid_hex}.qlog"))
      end
    end

    private def flush(connection, socket)
      connection.get_packets_to_send.each { |datagram| socket.send(datagram, 0) }
    end

    private def alpn_protocols_for(testcase)
      case testcase
      when "http3", "transfer" then ["h3"]
      else nil
      end
    end

    private def log(message)
      @logger.puts("[raiha-interop client] #{message}")
    end
  end
end
