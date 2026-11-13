# frozen_string_literal: true

require "socket"
require_relative "../error"
require_relative "../event"
require_relative "../iana"
require_relative "connection"
require_relative "event"

module Raiha::TLS
  module TCP
    # TLS over a TCP socket: a Connection driven by blocking reads and
    # writes, which a Fiber scheduler turns non-blocking. The one place in
    # the TLS layer that does I/O, reads the clock, and raises for what the
    # peer does: HandshakeError (CertificateError when a certificate did not
    # pass) for a failure, AlertError for the peer's alert, and EOFError when
    # the peer closes TCP without close_notify, which may have cut data
    # short. A stand-in for OpenSSL::SSL::SSLSocket where that is enough,
    # not a copy of it.
    class Socket
      # One record at most.
      READ_SIZE = 5 + (1 << 14) + 256

      # A failure with one of these alerts is about a certificate.
      CERTIFICATE_ALERTS = %i[
        bad_certificate unsupported_certificate certificate_revoked certificate_expired
        certificate_unknown unknown_ca certificate_required
      ].freeze

      # Connects to `host` and completes the handshake. With a block, yields
      # the socket and closes it after.
      def self.connect(host, port, config:, keyring:, server_name: host, keylog: nil)
        socket = start(::TCPSocket.new(host, port)) { Connection.client(config:, keyring:, server_name:, now: Time.now, keylog:) }
        return socket unless block_given?
        begin
          yield socket
        ensure
          socket.close
        end
      end

      # Takes the next connection on `listener` and completes the
      # handshake. With a block, yields the socket and closes it after.
      def self.accept(listener, config:, keyring:, keylog: nil)
        socket = start(listener.accept) { Connection.server(config:, keyring:, now: Time.now, keylog:) }
        return socket unless block_given?
        begin
          yield socket
        ensure
          socket.close
        end
      end

      # The socket over `io` once its handshake is done; `io` is closed if
      # it fails.
      private_class_method def self.start(io)
        new(io, yield)
      rescue Exception
        io.close
        raise
      end

      private_class_method :new

      attr_reader :alpn, :peer_certificates

      # Runs the handshake to completion.
      def initialize(io, connection)
        @io = io
        @connection = connection
        @alpn = nil #: String?
        # @type var peer_certificates: Array[OpenSSL::X509::Certificate]
        peer_certificates = []
        @peer_certificates = peer_certificates
        flush
        fill until @connection.handshake_complete?
        check
      end

      # Writes all of `data` and returns its size.
      def write(data)
        data = data.to_s.b
        offset = 0
        while offset < data.bytesize
          check
          offset += @connection.write(data.byteslice(offset..).to_s)
          flush
        end
        data.bytesize
      end

      # Up to `max_bytes` of the peer's data, waiting for some; nil once the
      # peer has sent close_notify and all is read.
      def read(max_bytes)
        loop do
          check
          data = @connection.read(max_bytes)
          return data unless data == ""
          fill
        end
      end

      # A KeyUpdate of our own, and of the peer's with
      # `request_peer_update: true`.
      def request_key_update(request_peer_update: false)
        @connection.request_key_update(request_peer_update:)
        flush
        nil
      end

      # Sends close_notify, if the connection still stands, and closes the
      # socket.
      def close
        unless @connection.failed?
          @connection.close_notify
          begin
            flush
          rescue IOError, SystemCallError
            # The peer is gone; there is nobody to tell.
          end
        end
        @io.close unless @io.closed?
        nil
      end

      private def flush
        @connection.each_output { |bytes| @io.write(bytes) }
      end

      # One read from the socket into the Connection, and whatever it has
      # to send back.
      private def fill
        bytes = @io.readpartial(READ_SIZE)
        @connection.receive(bytes, now: Time.now)
        flush
        check
      rescue EOFError
        check
        raise EOFError, "the peer closed TCP without close_notify"
      end

      # Raises for a failure or an alert from the peer, and keeps what the
      # handshake told.
      private def check
        while (event = @connection.next_event)
          case event
          when ::Raiha::TLS::Event::HandshakeComplete
            @alpn = event.alpn
            @peer_certificates = event.peer_certificates
          when ::Raiha::TLS::Event::Failed
            error = CERTIFICATE_ALERTS.include?(event.alert) ? CertificateError : HandshakeError
            raise error.new("TLS failed: #{event.reason} (#{event.alert || "no alert"})", alert: event.alert, reason: event.reason)
          when Event::PeerAlert
            next if IANA.alert_name(event.description) == :user_canceled
            raise AlertError.new(level: event.level, description: event.description)
          end
        end
      end
    end
  end
end
