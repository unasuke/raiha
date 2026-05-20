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

      # raiha only speaks HTTP/3 (no hq-interop / HTTP/0.9), so any
      # testcase that hands us REQUESTS gets fetched over h3. The
      # testcase classifier still drives flags like require_retry.
      use_http3 = requests.any? || Testcases.requires_http3?(@testcase)
      alpn = use_http3 ? ["h3"] : alpn_protocols_for(@testcase)

      log("starting testcase=#{@testcase} target=#{host}:#{port} requests=#{requests.size} alpn=#{alpn.inspect}")

      if @testcase == "resumption"
        return run_resumption(host: host, port: port, authority: authority,
                              alpn: alpn, requests: requests)
      end

      status, _ = run_single(host: host, port: port, authority: authority,
                             alpn: alpn, requests: requests, use_http3: use_http3)
      status
    rescue StandardError => error
      log("client error: #{error.class}: #{error.message}")
      log(error.backtrace.first(8).join("\n")) if error.backtrace
      1
    end

    # Connect once, run any HTTP/3 requests, then close. Returns
    # [exit_code, ticket_store_or_nil].
    private def run_single(host:, port:, authority:, alpn:, requests:,
                           use_http3:, session_ticket_store: nil)
      socket = build_socket(host, port)
      connection = Raiha::Connection.new(
        perspective: :client,
        src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
        dest_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
        server_name: authority,
        alpn_protocols: alpn,
        session_ticket_store: session_ticket_store
      )

      enable_observability(connection)
      connection.start_handshake
      flush(connection, socket)

      handshake_deadline = Time.now + DEFAULT_HANDSHAKE_DEADLINE
      until connection.handshake_complete?
        return [1, nil] if Time.now > handshake_deadline

        readable, = IO.select([socket], nil, nil, SELECT_TIMEOUT)
        if readable
          begin
            data, _ = socket.recvfrom(65535)
            connection.handle_packet(data)
          rescue Errno::ECONNREFUSED
            next
          end
        end
        connection.tick
        flush(connection, socket)
      end

      log("handshake complete")

      if use_http3 && requests.any?
        return [1, nil] unless run_http3_requests(connection, socket, requests, authority)
      end

      # Drain a little extra so a server-side NewSessionTicket (sent
      # right after our HTTP/3 request finishes) lands before we close.
      drain_for(connection, socket, seconds: 0.25)

      ticket_store = connection.tls_session_ticket_store
      connection.close
      flush(connection, socket)
      [0, ticket_store]
    end

    # RFC 8446 §2.2: resumption testcase fetches the requested URL(s)
    # on one connection, then opens a second connection that re-uses
    # the issued NewSessionTicket so the handshake completes via PSK.
    private def run_resumption(host:, port:, authority:, alpn:, requests:)
      if requests.empty?
        log("resumption requires REQUESTS")
        return 1
      end

      first_batch = [requests.first]
      second_batch = requests.length > 1 ? requests[1..] : [requests.first]

      log("resumption: first connection requests=#{first_batch.size}")
      first_status, ticket_store = run_single(
        host: host, port: port, authority: authority,
        alpn: alpn, requests: first_batch, use_http3: true
      )
      return first_status if first_status != 0
      if ticket_store.nil? || ticket_store.instance_variable_get(:@tickets).empty?
        log("resumption: server issued no ticket on first connection")
        return 1
      end

      log("resumption: second connection requests=#{second_batch.size}")
      second_status, _ = run_single(
        host: host, port: port, authority: authority,
        alpn: alpn, requests: second_batch, use_http3: true,
        session_ticket_store: ticket_store
      )
      second_status
    end

    private def drain_for(connection, socket, seconds:)
      deadline = Time.now + seconds
      while Time.now < deadline
        readable, = IO.select([socket], nil, nil, SELECT_TIMEOUT)
        if readable
          begin
            data, _ = socket.recvfrom_nonblock(65535)
            connection.handle_packet(data)
          rescue IO::WaitReadable, Errno::ECONNREFUSED
            break
          end
        end
        connection.tick
        flush(connection, socket)
      end
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
            loop do
              begin
                data, _ = socket.recvfrom_nonblock(65535)
              rescue IO::WaitReadable
                break
              rescue Errno::ECONNREFUSED
                break
              end
              connection.handle_packet(data)
            end
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
      # quic-interop-runner mounts /downloads inside the container
      # without exporting a corresponding env var; honour DOWNLOADS
      # when set (local smoke runs do this) and fall back to the
      # runner's well-known mount point.
      dir = @env["DOWNLOADS"]
      dir = "/downloads" if dir.nil? || dir.empty?

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
      # The Linux default for SO_RCVBUF (~212 KB) is too small for a
      # multi-MB burst from the server — recvfrom drops the overflow
      # before raiha gets a chance to read it. 8 MB matches what most
      # interop runners advertise as initial_max_data.
      socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 8 * 1024 * 1024)
      socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 8 * 1024 * 1024)
      socket.connect(host, port)
      socket
    end

    private def enable_observability(connection)
      qlog_dir = @env["QLOGDIR"]
      if qlog_dir && !qlog_dir.empty?
        FileUtils.mkdir_p(qlog_dir)
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
