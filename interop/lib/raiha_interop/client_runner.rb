# frozen_string_literal: true

require "fileutils"
require "socket"
require "uri"
require "raiha/connection"
require "raiha/http3/client"
require "raiha/quic/protocol/connection_id"

require_relative "testcases"

module RaihaInterop
  class ClientRunner
    SELECT_TIMEOUT = 0.05
    DEFAULT_HANDSHAKE_DEADLINE = 30 # seconds
    DEFAULT_REQUEST_DEADLINE = 60 # seconds

    def initialize(env:, testcase:, logger:)
      @env = env
      @testcase = testcase
      @logger = logger
    end

    def run
      requests = parse_requests(@env["REQUESTS"])
      first_uri = requests.first ? URI.parse(requests.first) : nil
      host, port = resolve_server(first_uri)
      authority = first_uri&.host || host

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

      handshake_deadline = Time.now + DEFAULT_HANDSHAKE_DEADLINE
      until connection.handshake_complete?
        return 1 if Time.now > handshake_deadline

        readable, = IO.select([socket], nil, nil, SELECT_TIMEOUT)
        if readable
          data, _ = socket.recvfrom(65535)
          connection.handle_packet(data)
        end
        connection.tick
        flush(connection, socket)
      end

      log("handshake complete")

      if Testcases.requires_http3?(@testcase) && requests.any?
        return 1 unless run_http3_requests(connection, socket, requests, authority)
      end

      connection.close
      flush(connection, socket)
      0
    rescue StandardError => error
      log("client error: #{error.class}: #{error.message}")
      log(error.backtrace.first(8).join("\n")) if error.backtrace
      1
    end

    private def run_http3_requests(connection, socket, requests, authority)
      http3 = Raiha::HTTP3::Client.new(connection: connection)
      http3.setup_control_stream
      flush(connection, socket)

      requests.each do |raw|
        uri = URI.parse(raw)
        path = uri.path.empty? ? "/" : uri.path
        path += "?#{uri.query}" if uri.query
        stream = http3.send_request(
          method: "GET",
          scheme: uri.scheme || "https",
          authority: uri.host || authority,
          path: path
        )
        flush(connection, socket)

        deadline = Time.now + DEFAULT_REQUEST_DEADLINE
        loop do
          return false if Time.now > deadline

          readable, = IO.select([socket], nil, nil, SELECT_TIMEOUT)
          if readable
            data, _ = socket.recvfrom(65535)
            connection.handle_packet(data)
          end
          connection.tick
          flush(connection, socket)

          peer_stream = connection.streams.get_stream(stream.stream_id.value)
          break if peer_stream && peer_stream.fin_received?
        end

        peer_stream = connection.streams.get_stream(stream.stream_id.value)
        response = http3.receive_response(peer_stream)
        write_download(uri, response.body)
      end
      true
    end

    private def write_download(uri, body)
      dir = @env["DOWNLOADS"]
      return if dir.nil? || dir.empty?

      FileUtils.mkdir_p(dir)
      filename = File.basename(uri.path)
      filename = "index" if filename.nil? || filename.empty? || filename == "/"
      File.binwrite(File.join(dir, filename), body || "")
    end

    private def resolve_server(uri)
      target = @env["WAITFORSERVER"] || @env["SERVER"]
      if target
        host, port = target.split(":")
        return [host, (port || @env["PORT"] || 443).to_i]
      end
      raise "no WAITFORSERVER and no REQUESTS to derive host from" unless uri
      [uri.host, uri.port || 443]
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
      Testcases.requires_http3?(testcase) ? ["h3"] : nil
    end

    private def log(message)
      @logger.puts("[raiha-interop client] #{message}")
    end
  end
end
