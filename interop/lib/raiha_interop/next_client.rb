# frozen_string_literal: true

require "uri"
require_relative "next_quic"

module RaihaInterop
  # The client of hq-interop on the next release of raiha: one connection
  # to the server of the first of REQUESTS, a stream for each of them,
  # "GET /path\r\n" on it, and what comes back saved under DOWNLOADS by the
  # name of the path. The chacha20 testcase offers ChaCha20-Poly1305 alone,
  # without GREASE; versionnegotiation only elicits a Version Negotiation
  # packet.
  class NextClient
    include NextQUIC

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
      # The paths not yet asked for, the requests not yet all written, and
      # the paths and bodies of the streams by their IDs.
      @queue = []
      @unwritten = {}
      @bodies = {}
      @saved = 0
    end

    def run
      urls = (@env["REQUESTS"] || "").split
      raise "no REQUESTS" if urls.empty?
      uri = URI(urls.first)
      remote = resolve(uri)
      return probe_version_negotiation(remote) if @testcase == "versionnegotiation"
      @queue = urls.map { |url| URI(url).path }
      socket = udp_socket
      socket.bind("0.0.0.0", 0)
      connection = connect(uri.host, remote)
      log("connecting to #{remote.inspect} testcase=#{@testcase} requests=#{@queue.size}")
      limit = mono + DEADLINE
      total = @queue.size
      until @saved == total || connection.closed? || connection.draining? || mono > limit
        connection.each_transmit(now: mono) { |transmit| send_transmit(socket, transmit) }
        receive_datagrams(socket, [connection.next_timeout, limit].compact.min).each do |data, from|
          connection.receive(data, from:, now: mono)
        end
        deadline = connection.next_timeout
        connection.handle_timeout(now: mono) if deadline && deadline <= mono
        step(connection)
      end
      log("saved #{@saved} of #{total}; #{connection.close_reason.inspect}")
      connection.close(now: mono)
      connection.each_transmit(now: mono) { |transmit| send_transmit(socket, transmit) }
      @saved == total ? 0 : 1
    rescue StandardError => error
      log("client error: #{error.class}: #{error.message}")
      log(error.backtrace.first(8).join("\n")) if error.backtrace
      1
    end

    # For chacha20, the runner reads the first cipher suite of the
    # ClientHello as Wireshark gives it, which a GREASE value would be: the
    # ClientHello goes without GREASE then.
    private def connect(server_name, remote)
      chacha20 = @testcase == "chacha20"
      cipher_suites = chacha20 ? %i[TLS_CHACHA20_POLY1305_SHA256] : TLS::Config::DEFAULT_CIPHER_SUITES
      tls_config = TLS::Config.client(profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY, cipher_suites:, grease: !chacha20,
        trust_anchors: certificates_der(File.join(certs_dir, "ca.pem")))
      QUIC::Connection.client(config: QUIC::Config.new, tls_config:, keyring: TLS::Keyring.client(config: tls_config), server_name:,
        remote:, time: Time.now, now: mono, tracer: qlog(:client), keylog:)
    end

    # A turn of the application: a stream for each path while the server
    # lets more open, and what came back saved once a stream has ended.
    private def step(connection)
      connection.each_event { |event| log("closed: #{event.error.inspect}") if event.is_a?(QUIC::Event::Closed) }
      return unless connection.handshake_complete?
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

    private def take_response(connection, stream_id)
      path, body = @bodies.fetch(stream_id)
      while (chunk = connection.stream_read(stream_id, PIECE))
        return if chunk.empty?
        body << chunk
      end
      @bodies.delete(stream_id)
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
