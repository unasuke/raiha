# frozen_string_literal: true

require "fileutils"
require "openssl"
require "securerandom"
require "socket"
require "raiha/next/quic"

module RaihaInterop
  # What the client and the server of the next release of raiha share:
  # the TLS extensions with the QUIC transport parameters, hq-interop
  # (HTTP/0.9 over QUIC) for ALPN, a UDP socket with room for bursts, and
  # the keylog and the qlog quic-interop-runner asks for.
  module NextQUIC
    QUIC = Raiha::Next::QUIC
    TLS = Raiha::Next::TLS
    REGISTRY = TLS::Extension::Registry::BUILTIN.with(QUIC::TransportParameters::Extension)
    ALPN = ["hq-interop"].freeze
    # The Linux default for the receive buffer (about 212 KB) is too small
    # for a burst of several MB: the kernel drops what overflows before it
    # is read.
    SOCKET_BUFFER = 8 * 1024 * 1024
    # The most datagrams taken from the socket before the application runs.
    RECEIVE_BATCH = 64

    def mono = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    def udp_socket
      socket = UDPSocket.new
      socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, SOCKET_BUFFER)
      socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, SOCKET_BUFFER)
      socket
    end

    # Sends a datagram the connection or the Endpoint put out. A peer gone
    # away is no reason to stop.
    def send_transmit(socket, transmit)
      socket.send(transmit.payload, 0, *transmit.destination)
    rescue Errno::ECONNREFUSED, Errno::EMSGSIZE => error
      log("dropped a datagram of #{transmit.payload.bytesize} bytes to #{transmit.destination.inspect}: #{error.class}")
    end

    # The datagrams on `socket` as [data, [address, port]]: waits for the
    # first until `deadline` (forever when nil), then takes those there
    # already, RECEIVE_BATCH at most.
    def receive_datagrams(socket, deadline)
      timeout = deadline && [deadline - mono, 0].max
      return [] unless IO.select([socket], nil, nil, timeout)
      datagrams = []
      while datagrams.size < RECEIVE_BATCH
        data, address = socket.recvfrom_nonblock(65_535, exception: false)
        break if data == :wait_readable || data.nil?
        datagrams << [data, [address[3], address[1]]]
      end
      datagrams
    rescue Errno::ECONNREFUSED
      datagrams || []
    end

    # The keylog of SSLKEYLOGFILE, nil when it is not set.
    def keylog
      path = @env["SSLKEYLOGFILE"]
      TLS::Keylog::File.new(path) unless path.nil? || path.empty?
    end

    # A qlog of a connection to come, in a file of its own in QLOGDIR; nil
    # when it is not set.
    def qlog(vantage_point)
      dir = @env["QLOGDIR"]
      return nil if dir.nil? || dir.empty?
      FileUtils.mkdir_p(dir)
      io = File.open(File.join(dir, "#{vantage_point}-#{SecureRandom.hex(4)}.sqlog"), "w")
      io.sync = true
      QUIC::Qlog::Tracer.new(io, vantage_point:)
    end

    # The certificates of a PEM file, DER-encoded.
    def certificates_der(path)
      File.read(path).scan(/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/m).map do |pem|
        OpenSSL::X509::Certificate.new(pem).to_der
      end
    end

    def certs_dir = @env["CERTS"] || "/certs"
  end
end
