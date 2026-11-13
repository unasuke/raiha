# frozen_string_literal: true

require "fileutils"
require "openssl"
require "securerandom"
require "socket"
require "raiha/quic"
require "raiha/runtime"

module RaihaInterop
  # What the client and the server of raiha share:
  # the TLS extensions with the QUIC transport parameters, hq-interop
  # (HTTP/0.9 over QUIC) for ALPN, the runtime's UDP socket, and the keylog
  # and the qlog quic-interop-runner asks for. With
  # RAIHA_STARTUP=rapid_start, the paths start with Rapid Start.
  module Common
    QUIC = Raiha::QUIC
    TLS = Raiha::TLS
    REGISTRY = TLS::Extension::Registry::BUILTIN.with(QUIC::TransportParameters::Extension)
    ALPN = ["hq-interop"].freeze

    STARTUPS = { "" => nil, "rapid_start" => QUIC::Congestion::Startup::RapidStart }.freeze

    def mono = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    # The QUIC Config of a connection, with the startup RAIHA_STARTUP names.
    def quic_config
      name = @env["RAIHA_STARTUP"] || ""
      QUIC::Config.new(startup: STARTUPS.fetch(name) { raise ArgumentError, "unknown RAIHA_STARTUP #{name.inspect}" })
    end

    # The protocol offered and taken with ALPN.
    def alpn = ALPN

    # The runtime's UDP socket bound to `host` and `port`: it marks each
    # datagram with the ECN codepoint of its Transmit and reads the one each
    # that comes in was marked with, which ECN validation and the runner's
    # ecn testcase need, with buffers large enough for a burst.
    def udp_socket(host, port) = Raiha::Runtime::UDP.bind(host, port)

    # Sends what the connection or the Endpoint put out. A peer gone away is
    # no reason to stop: what does not go is dropped.
    def send_transmit(socket, transmit)
      return if socket.send(transmit)
      log("dropped a datagram of #{transmit.payload.bytesize} bytes to #{transmit.destination.inspect}")
    end

    # The datagrams on `sockets`, one socket or several, as [data,
    # [address, port] it came from, [address, port] it came to, ecn]: waits
    # for the first until `deadline` (forever when nil), then takes those
    # there already, as many as each socket takes at once.
    def receive_datagrams(sockets, deadline)
      timeout = deadline && [deadline - mono, 0].max
      ready, = IO.select(Array(sockets), nil, nil, timeout)
      (ready || []).flat_map(&:receive)
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
