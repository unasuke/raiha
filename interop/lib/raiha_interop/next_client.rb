# frozen_string_literal: true

require "uri"
require_relative "next_quic"

module RaihaInterop
  # The client of hq-interop on the next release of raiha: one connection
  # to the server of the first of REQUESTS, a stream for each of them,
  # "GET /path\r\n" on it, and what comes back saved under DOWNLOADS by the
  # name of the path. The chacha20 testcase offers ChaCha20-Poly1305 alone,
  # without GREASE; versionnegotiation only elicits a Version Negotiation
  # packet. For resumption and zerortt, the first path is fetched on a
  # connection of its own, which waits for a ticket, and the rest on a
  # second that resumes it, in 0-RTT for zerortt; what a rejected 0-RTT
  # asked for is asked again.
  class NextClient
    include NextQUIC

    RESUMING = %w[resumption zerortt].freeze

    # How long the client tries before it gives up.
    DEADLINE = 120
    # QUIC draft-29, which the server is not expected to take: Wireshark,
    # which the runner reads the trace with, gives the packet types of its
    # long header, as it does not for a version reserved for negotiation.
    PROBE_VERSION = 0xff00001d
    # How often the probe goes again while nothing answers it.
    PROBE_INTERVAL = 1.0
    PIECE = 65_536

    def initialize(env:, testcase:, logger:)
      @env = env
      @testcase = testcase
      @logger = logger
      # The paths not yet asked for, the requests not yet all written, the
      # paths and bodies of the streams by their IDs, and the tickets the
      # server gave, of the connection under way.
      @queue = []
      @unwritten = {}
      @bodies = {}
      @saved = 0
      @tickets = []
    end

    def run
      urls = (@env["REQUESTS"] || "").split
      raise "no REQUESTS" if urls.empty?
      uri = URI(urls.first)
      remote = resolve(uri)
      return probe_version_negotiation(remote) if @testcase == "versionnegotiation"
      paths = urls.map { |url| URI(url).path }
      return fetch(uri.host, remote, paths).first ? 0 : 1 unless RESUMING.include?(@testcase)
      first, *rest = paths
      fetched, ticket = fetch(uri.host, remote, [first], wait_for_ticket: true)
      return 1 unless fetched && ticket
      fetch(uri.host, remote, rest, session: ticket, early_data: @testcase == "zerortt").first ? 0 : 1
    rescue StandardError => error
      log("client error: #{error.class}: #{error.message}")
      log(error.backtrace.first(8).join("\n")) if error.backtrace
      1
    end

    # Fetches `paths` on a connection of its own, resuming `session`, in
    # 0-RTT with `early_data`, and with `wait_for_ticket` until the server
    # has given a ticket as well: whether all were saved, and the newest
    # ticket.
    private def fetch(server_name, remote, paths, session: nil, early_data: false, wait_for_ticket: false)
      @queue = paths.dup
      @unwritten = {}
      @bodies = {}
      @saved = 0
      @tickets = []
      socket = udp_socket
      socket.bind("0.0.0.0", 0)
      connection = connect(server_name, remote, session:, early_data:)
      log("connecting to #{remote.inspect} testcase=#{@testcase} requests=#{paths.size} resuming=#{!session.nil?} 0-RTT=#{connection.zero_rtt_state}")
      limit = mono + DEADLINE
      # The application's turn comes first, so that requests in 0-RTT go
      # with the first Initial rather than after the server's flight.
      until (@saved == paths.size && (!wait_for_ticket || !@tickets.empty?)) || connection.closed? || connection.draining? || mono > limit
        step(connection)
        connection.each_transmit(now: mono) { |transmit| send_transmit(socket, transmit) }
        receive_datagrams(socket, [connection.next_timeout, limit].compact.min).each do |data, from|
          connection.receive(data, from:, now: mono)
        end
        deadline = connection.next_timeout
        connection.handle_timeout(now: mono) if deadline && deadline <= mono
      end
      log("saved #{@saved} of #{paths.size}; tickets=#{@tickets.size} 0-RTT=#{connection.zero_rtt_state}; #{connection.close_reason.inspect}")
      connection.close(now: mono)
      connection.each_transmit(now: mono) { |transmit| send_transmit(socket, transmit) }
      [@saved == paths.size, @tickets.last]
    ensure
      socket&.close
    end

    # For chacha20, the runner reads the first cipher suite of the
    # ClientHello as Wireshark gives it, which a GREASE value would be: the
    # ClientHello goes without GREASE then.
    private def connect(server_name, remote, session:, early_data:)
      chacha20 = @testcase == "chacha20"
      cipher_suites = chacha20 ? %i[TLS_CHACHA20_POLY1305_SHA256] : TLS::Config::DEFAULT_CIPHER_SUITES
      tls_config = TLS::Config.client(profile: TLS::Profile::QUIC, alpn:, registry: REGISTRY, cipher_suites:, grease: !chacha20,
        trust_anchors: certificates_der(File.join(certs_dir, "ca.pem")))
      QUIC::Connection.client(config: QUIC::Config.new, tls_config:, keyring: TLS::Keyring.client(config: tls_config), server_name:,
        remote:, time: Time.now, now: mono, tracer: qlog(:client), keylog:, session:, early_data:)
    end

    # A turn of the application: a stream for each path while the server
    # lets more open, in 0-RTT while it goes, and what came back saved once
    # a stream has ended.
    private def step(connection)
      connection.each_event { |event| take(connection, event) }
      return unless connection.handshake_complete? || connection.zero_rtt_state == :pending
      return if connection.closing? || connection.draining? || connection.closed?
      while !@queue.empty? && (stream_id = connection.open_stream)
        path = @queue.shift
        @bodies[stream_id] = [path, "".b]
        @unwritten[stream_id] = "GET #{path}\r\n".b
      end
      @unwritten.each do |stream_id, request|
        @unwritten[stream_id] = request.byteslice(connection.stream_write(stream_id, request, fin: true)..) || "".b
      end
      @unwritten.delete_if { |_, request| request.empty? }
      connection.readable_streams.to_a.each { |stream_id| take_response(connection, stream_id) }
    end

    private def take(connection, event)
      case event
      when QUIC::Event::Closed then log("closed: #{event.error.inspect}")
      when QUIC::Event::SessionTicket then @tickets << event.session
      when QUIC::Event::ZeroRttRejected
        # The streams are gone: what they asked for is asked again in 1-RTT.
        log("0-RTT rejected: #{event.reason}")
        @queue = @bodies.values.map(&:first) + @queue
        @bodies.clear
        @unwritten.clear
        connection.acknowledge_zero_rtt_rejection
      end
    end

    private def take_response(connection, stream_id)
      path, body = @bodies.fetch(stream_id)
      while (chunk = connection.stream_read(stream_id, PIECE))
        return if chunk.empty?
        body << chunk
      end
      @bodies.delete(stream_id)
      save(path, body)
    end

    # Saves `body` under DOWNLOADS by the name of `path`.
    private def save(path, body)
      dir = @env["DOWNLOADS"] || "/downloads"
      FileUtils.mkdir_p(dir)
      File.binwrite(File.join(dir, File.basename(path)), body)
      @saved += 1
    end

    # A datagram of 1200 bytes with the long header of an Initial of
    # PROBE_VERSION, which the server answers with a Version Negotiation
    # packet that echoes its connection IDs (RFC 9000 "Version
    # Negotiation"); the rest of the packet is never read.
    private def probe_version_negotiation(remote)
      socket = udp_socket
      socket.bind("0.0.0.0", 0)
      dcid = SecureRandom.bytes(8)
      scid = SecureRandom.bytes(8)
      header = [0xc0, PROBE_VERSION, dcid.bytesize].pack("CNC") + dcid + [scid.bytesize].pack("C") + scid + [0, 0x44b0].pack("Cn")
      probe = header + SecureRandom.bytes(1200 - header.bytesize)
      limit = mono + DEADLINE
      until mono > limit
        socket.send(probe, 0, *remote)
        receive_datagrams(socket, mono + PROBE_INTERVAL).each do |data, _|
          packet = QUIC::Wire::Packet.parse(data, dcid_length: scid.bytesize)
          next unless packet.is_a?(QUIC::Wire::VersionNegotiation) && packet.dcid == scid && packet.scid == dcid
          log("versions the server takes: #{packet.versions.map { |version| format("0x%08x", version) }.join(", ")}")
          return 0
        rescue QUIC::Wire::Malformed
          next
        end
      end
      1
    end

    # The address of the server of `uri`, as [address, port].
    private def resolve(uri)
      address = Addrinfo.getaddrinfo(uri.host, uri.port || 443, :INET, :DGRAM).first or raise "#{uri.host} does not resolve"
      [address.ip_address, address.ip_port]
    end

    private def log(message) = @logger.puts("[raiha-interop next client] #{message}")
  end
end
