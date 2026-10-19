# frozen_string_literal: true

module Raiha::Next::QUIC
  # The one place of the QUIC layer that drives the TLS layer's handshake
  # Machine. It carries TLS's messages in the CRYPTO
  # frames of each encryption level and hands those it receives to the
  # Machine by RFC 9001 "Sending and Receiving Handshake Messages": the
  # current level's in order, a finished level's never past what it had
  # received, a later level's kept until the Machine reads it. What the
  # Machine puts out it tells the connection: keys to install, the peer's
  # transport parameters, the handshake complete, a failure as an error
  # code, and other events to pass on.
  #
  # TLS's epochs keep their names inside the Machine; the connection sees
  # QUIC's levels, mapped by LEVEL.
  class TLSBinding
    LEVEL = { initial: :initial, early_data: :zero_rtt, handshake: :handshake, application: :one_rtt }.freeze
    EPOCH = LEVEL.invert.freeze
    # The levels in the order a handshake goes through them.
    RANK = { initial: 0, zero_rtt: 1, handshake: 2, one_rtt: 3 }.freeze
    # The number space of each level that carries CRYPTO frames.
    SPACES = { initial: :initial, handshake: :handshake, one_rtt: :application_data }.freeze
    LEVEL_OF_SPACE = SPACES.invert.freeze
    # RFC 9000 "Cryptographic Message Buffering": an endpoint buffers at
    # least this much, whatever TLS says it needs.
    MIN_CRYPTO_BUFFER = 4096
    TRANSPORT_PARAMETERS = 0x39

    # A client's binding, with the ClientHello already in its Initial CRYPTO
    # stream. `transport_parameters` are this end's; `time` is the wall
    # clock TLS takes. `tracer` is the connection's, which TLS is given only
    # when it takes TLS's traces with `tls_trace`.
    def self.client(connection:, config:, keyring:, server_name:, transport_parameters:, time:, tracer: nil, keylog: nil)
      check(config)
      machine = Raiha::Next::TLS::Handshake::Machine.client(
        config:, keyring:, server_name:, now: time, extensions: [extension(transport_parameters)], tracer: tls_tracer(tracer), keylog:
      )
      new(connection, machine, config.profile).tap { |binding| binding.pump }
    end

    # A server's binding, given the ClientHello an Acceptor took when there
    # was one. Its bytes are the start of the Initial CRYPTO stream, so the
    # frames that carried them, received again, are not read twice.
    def self.server(connection:, config:, keyring:, transport_parameters:, time:, client_hello: nil, tracer: nil, keylog: nil)
      check(config)
      machine = Raiha::Next::TLS::Handshake::Machine.server(
        config:, keyring:, client_hello:, now: time, extensions: [extension(transport_parameters)], tracer: tls_tracer(tracer), keylog:
      )
      new(connection, machine, config.profile, consumed: client_hello&.bytes&.bytesize || 0).tap { |binding| binding.pump }
    end

    private_class_method def self.check(config)
      return if config.profile == Raiha::Next::TLS::Profile::QUIC
      raise ArgumentError, "the TLS Config of a QUIC connection has the QUIC profile"
    end

    private_class_method def self.tls_tracer(tracer) # steep:ignore
      tracer if tracer.respond_to?(:tls_trace) # steep:ignore
    end

    private_class_method def self.extension(transport_parameters)
      Raiha::Next::TLS::Extension::Opaque.new(type: TRANSPORT_PARAMETERS, data: transport_parameters.encode)
    end

    # `consumed` Initial CRYPTO bytes have been read already.
    def initialize(connection, machine, profile, consumed: 0)
      @connection = connection
      @machine = machine
      @profile = profile
      @streams = SPACES.to_h { |level, space| [level, CryptoStream.new(space)] } #: Hash[PacketProtection::level, CryptoStream]
      @streams.fetch(:initial).consumed(consumed)
    end

    def complete? = @machine.complete?

    # A CRYPTO frame of `level` received. Bytes of a finished level past what
    # it had received are PROTOCOL_VIOLATION; a frame without bytes carries
    # none.
    def receive_crypto(level, frame, time:)
      return if frame.data.empty?
      stream = @streams[level] or return
      finish = frame.offset + frame.data.bytesize
      if RANK.fetch(level) < RANK.fetch(read_level) && finish > stream.received_end
        raise Violation.new("CRYPTO data past the end of the #{level} level, which TLS has left", frame_type: CryptoStream::FRAME_TYPE)
      end
      stream.receive(frame.offset, frame.data, limit: [MIN_CRYPTO_BUFFER, @machine.max_flight_size(EPOCH.fetch(level))].max)
      feed(time) if level == read_level
    end

    # Tells the connection what the Machine has put out. A message of a
    # level whose keys are gone has nowhere to go.
    def pump
      @machine.each_output do |output|
        case output
        in Raiha::Next::TLS::Output::Message(epoch:, bytes:) then @streams[LEVEL.fetch(epoch)]&.write(bytes)
        in Raiha::Next::TLS::Output::Secret(epoch:, direction:, secret:, cipher_suite:)
          @connection.install_keys(LEVEL.fetch(epoch), direction, secret:, suite: cipher_suite)
        in Raiha::Next::TLS::Output::Alert then nil
        end
      end
      @machine.each_event do |event|
        case event
        in Raiha::Next::TLS::Event::PeerExtension(type: TRANSPORT_PARAMETERS, data:) then @connection.peer_transport_parameters(data)
        in Raiha::Next::TLS::Event::HandshakeComplete then @connection.handshake_completed(event)
        in Raiha::Next::TLS::Event::Failed(alert:, reason:) then @connection.tls_failed(error_code(alert, reason), reason)
        else @connection.tls_event(event)
        end
      end
    end

    def crypto_pending?(level) = @streams[level]&.pending? || false

    # The next CRYPTO frame of `level` and its duty, in `room` bytes.
    def next_crypto_frame(level, room) = @streams[level]&.next_frame(room)

    def crypto_acked(duty) = stream_of(duty)&.acked(duty.offset, duty.length)

    # Lost bytes of a level whose keys are gone are not sent again.
    def crypto_lost(duty) = stream_of(duty)&.lost(duty.offset, duty.length)

    # The keys of `level` are gone: so are its CRYPTO frames.
    def discard_level(level) = @streams.delete(level)

    # The connection ended other than by TLS failing: the Machine forgets its
    # secrets.
    def discard = @machine.discard

    private def read_level = LEVEL.fetch(@machine.read_epoch)

    # Hands the bytes of the level TLS reads to the Machine, again as long as
    # what it puts out moves it to a level with bytes waiting. Bytes of a
    # level TLS leaves that it has not read, past a gap, are
    # PROTOCOL_VIOLATION (RFC 9001 "Sending and Receiving Handshake
    # Messages").
    private def feed(time)
      until @machine.failed?
        epoch = @machine.read_epoch
        stream = @streams[LEVEL.fetch(epoch)] or break
        bytes = stream.read
        break if bytes.empty?
        @machine.receive(bytes, epoch:, now: time)
        pump
        if @machine.read_epoch != epoch && !@machine.failed? && stream.buffered.positive?
          raise Violation.new("CRYPTO data of the #{LEVEL.fetch(epoch)} level unread as TLS leaves it", frame_type: CryptoStream::FRAME_TYPE)
        end
      end
    end

    private def stream_of(duty) = @streams[LEVEL_OF_SPACE.fetch(duty.space)]

    # RFC 9001 "TLS Errors": an alert as CRYPTO_ERROR, and the failures RFC
    # 9001 names as PROTOCOL_VIOLATION.
    private def error_code(alert, reason)
      return ErrorCode::PROTOCOL_VIOLATION if @profile.protocol_violation_reasons.include?(reason)
      alert ? ErrorCode.crypto_error(Raiha::Next::TLS::IANA.alert_code(alert)) : ErrorCode::INTERNAL_ERROR
    end
  end
end
