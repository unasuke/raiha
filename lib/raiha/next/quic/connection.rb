# frozen_string_literal: true

module Raiha::Next::QUIC
  # One QUIC connection, sans-IO: it is
  # given datagrams with `receive` and the time with `handle_timeout`, and
  # hands back the datagrams to send with `each_transmit` and what happened
  # with `each_event`. It never reads a clock; `now:` is the monotonic
  # clock in Float seconds, and TLS's wall clock is `time:`, given once when
  # the connection is made, moved on by the monotonic clock since.
  #
  # A connection knows only itself: an Endpoint finds it by connection ID.
  class Connection
    # The encryption levels, in the order their packets go in a datagram.
    LEVELS = %i[initial zero_rtt handshake one_rtt].freeze
    # The packet number space of each level.
    SPACES = { initial: :initial, zero_rtt: :application_data, handshake: :handshake, one_rtt: :application_data }.freeze
    # RFC 9000 "Datagram Size": a datagram with an Initial packet in it
    # from a client, or with an ack-eliciting one from a server, is padded
    # to this.
    MIN_INITIAL_DATAGRAM = 1200
    # The length of a client's first Destination Connection ID (RFC 9000
    # "Negotiating Connection IDs": 8 bytes at least).
    INITIAL_DCID_LENGTH = 8
    # The ACK Delay exponent before the peer's is known, and for the ACK
    # frames of Initial and Handshake packets.
    DEFAULT_ACK_DELAY_EXPONENT = 3
    # Bytes a long header adds to its connection IDs and token, with a
    # 2-byte Length and a 4-byte packet number at most, and the AEAD tag.
    LONG_HEADER_OVERHEAD = 1 + 4 + 1 + 1 + 2 + 4 + 16
    SHORT_HEADER_OVERHEAD = 1 + 4 + 16

    # RFC 9000 "Immediate Close": the closing and draining states last three
    # PTOs.
    CLOSE_PTOS = 3
    # The longest reason phrase a CONNECTION_CLOSE frame carries.
    MAX_REASON_LENGTH = 256
    # The levels a CONNECTION_CLOSE frame goes in.
    CLOSE_LEVELS = %i[initial handshake one_rtt].freeze

    # RFC 9000 "Address Validation": until it has validated the client's
    # address, a server sends at most this many times what it received.
    AMPLIFICATION_FACTOR = 3

    # A packet put together, not yet protected.
    Pending = Data.define(:level, :header, :packet_number, :packet_number_length, :frames, :duties)

    attr_reader :role, :path

    # A client connection to `remote` ([host, port]), with its first
    # Initial packet waiting to be sent. `tls_config` has the QUIC profile.
    # The connection's Source Connection ID is `source_connection_id`, which
    # an Endpoint routes by, or one of its own.
    def self.client(config:, tls_config:, keyring:, server_name:, remote:, time:, now:, tracer: nil, keylog: nil, source_connection_id: nil)
      new(role: :client, config:, now:, time:, remote:, tracer:, random: keyring.random, source_connection_id:) do |connection, parameters|
        TLSBinding.client(connection:, config: tls_config, keyring:, server_name:, transport_parameters: parameters, time:, tracer:, keylog:)
      end
    end

    # A server connection, which takes the client's first Initial packet as
    # it comes and starts TLS then, when the client's first Destination
    # Connection ID, which its transport parameters carry, is known.
    #
    # An Endpoint that has taken the offer of the connection gives what it
    # learned: the ClientHello its Acceptor read (`client_hello`), and after
    # a Retry the client's first Destination Connection ID and the Retry's
    # Source Connection ID, which the transport parameters name, and that
    # the client's address is validated. It also chooses the connection's
    # Source Connection ID, and gives its `stateless_reset_token`, which the
    # transport parameters carry (RFC 9000 "Stateless Reset").
    def self.server(config:, tls_config:, keyring:, time:, now:, tracer: nil, keylog: nil, client_hello: nil,
      original_destination_connection_id: nil, retry_source_connection_id: nil, address_validated: false, source_connection_id: nil,
      stateless_reset_token: nil)
      new(role: :server, config:, now:, time:, remote: nil, tracer:, random: keyring.random, original_destination_connection_id:,
        retry_source_connection_id:, address_validated:, source_connection_id:, stateless_reset_token:) do |connection, parameters|
        TLSBinding.server(connection:, config: tls_config, keyring:, transport_parameters: parameters, time:, client_hello:, tracer:, keylog:)
      end
    end

    private_class_method :new

    def initialize(role:, config:, now:, time:, remote:, tracer:, random:, original_destination_connection_id: nil,
      retry_source_connection_id: nil, address_validated: role == :client, source_connection_id: nil, stateless_reset_token: nil, &start)
      @role = role
      @config = config
      @version = config.versions.fetch(0)
      @created_at = now
      @time = time
      @remote = remote
      @tracer = tracer
      @path = Path.new(config:, tracer:)
      @recovery = Recovery.new(role:, config:, path: @path, random:, now:, tracer:)
      @events = [] #: Array[Event::t]
      @streams = Streams.new(role:, config:, events: @events, now:)
      @protection = PacketProtection.new(role:, version: @version) { |phase| keys_updated(phase) }
      @source_connection_id = source_connection_id || random.bytes(config.connection_id_length).b
      @stateless_reset_token = stateless_reset_token
      @peer_parameters = nil #: TransportParameters?
      @handshake_complete = false
      @handshake_confirmed = false
      @handshake_done_due = false
      # The Source Connection ID of the peer's first Initial packet; a long
      # header packet with another is dropped (RFC 9000 "Negotiating
      # Connection IDs").
      @peer_source_connection_id = nil #: String?
      # :open, :closing, :draining or :closed (RFC 9000 "Connection
      # Termination").
      @state = :open
      @close_error = nil #: ConnectionError?
      @close_deadline = nil #: Float?
      @close_frame_due = false
      @closing_datagrams = 0
      @idle_deadline = nil #: Float?
      @eliciting_since_received = false
      @now = now
      # What a server has received and sent while the client's address is
      # not validated, and whether that has stopped it.
      @address_validated = address_validated
      @received_unvalidated = 0
      @sent_unvalidated = 0
      @amplification_limited = false
      # How many packets that elicit an ACK a PTO asks for in each space.
      @probes = {} #: Hash[space, Integer]
      restart_idle(now)
      @start_binding = start
      @binding = nil #: TLSBinding?
      # A client's first Destination Connection ID, and the Source
      # Connection ID of a Retry, which the server's transport parameters
      # must name.
      @original_destination_connection_id = original_destination_connection_id
      @retry_source_connection_id = retry_source_connection_id
      # The token a client's Initials carry, from a Retry.
      @token = Wire::EMPTY
      # The stateless reset tokens the peer gave.
      @reset_tokens = [] #: Array[String]
      if role == :client
        @destination_connection_id = random.bytes(INITIAL_DCID_LENGTH).b
        @original_destination_connection_id = @destination_connection_id
        @protection.install_initial(@destination_connection_id)
        parameters = config.transport_parameters(initial_source_connection_id: @source_connection_id)
        @tracer.parameters_set(owner: :local, parameters:, now:) if @tracer # steep:ignore
        @binding = start.call(self, parameters)
      else
        @destination_connection_id = "".b
      end
    end

    # Whether TLS has completed the handshake on this end.
    def handshake_complete? = @handshake_complete

    # Whether the handshake is confirmed (RFC 9001 "Handshake Confirmed"): on
    # a server once it is complete, on a client once HANDSHAKE_DONE comes.
    def handshake_confirmed? = @handshake_confirmed

    def closing? = @state == :closing

    def draining? = @state == :draining

    # Whether the connection is over, its closing or draining period past.
    def closed? = @state == :closed

    # Why the connection closed, nil while it is open.
    def close_reason = @close_error

    # Up to `max_bytes` received on `stream_id`, read by the application:
    # "" when nothing is there yet, nil once the stream has ended, as
    # IO#read gives. What is read goes back to the peer as credit.
    def stream_read(stream_id, max_bytes) = @streams.read(stream_id, max_bytes)

    # The streams a read would give something on.
    def readable_streams = @streams.readable.each

    # Opens a stream going `direction`, :bidi or :uni: its ID, or nil when
    # the peer allows no more yet.
    def open_stream(direction: :bidi)
      raise ArgumentError, "a stream goes :bidi or :uni, not #{direction.inspect}" unless %i[bidi uni].include?(direction)
      open!
      @streams.open(direction, now: @now)
    end

    # Writes `data` to `stream_id`, as much of it as the stream's credit,
    # the connection's and the send buffer leave room for, and ends the
    # stream with `fin` when all of it is taken: how many bytes were taken.
    # Less than all of it, and Event::StreamWritable tells when the stream
    # can take more.
    def stream_write(stream_id, data, fin: false)
      open!
      @streams.write(stream_id, data, fin:)
    end

    # How many bytes a write to `stream_id` would take now.
    def stream_writable_bytes(stream_id) = @streams.writable_bytes(stream_id)

    # Abandons sending on `stream_id`: RESET_STREAM goes with
    # `error_code`, and what was written and not acknowledged goes nowhere.
    def stream_reset(stream_id, error_code:)
      open!
      @streams.reset(stream_id, error_code)
    end

    # Stops reading `stream_id`: STOP_SENDING asks the peer with
    # `error_code` to stop sending, and what comes is let go.
    def stream_stop_sending(stream_id, error_code:)
      open!
      @streams.stop_sending(stream_id, error_code)
    end

    # The streams a write would take something on.
    def writable_streams = @streams.writable.each

    # Closes the connection with `error_code`, an application's unless
    # `application` is false: a CONNECTION_CLOSE frame goes out, and the
    # connection stays closing, answering what comes with it again, for
    # three PTOs (RFC 9000 "Immediate Close"). `each_transmit` and
    # `handle_timeout` still have work until `closed?`.
    def close(error_code: ErrorCode::NO_ERROR, reason: "", application: true, now:)
      @now = now
      return unless @state == :open
      enter_closing(ConnectionError.new(code: error_code, frame_type: application ? nil : 0, reason:, application:), now)
    end

    def next_event = @events.shift

    def each_event
      while (event = @events.shift)
        yield event
      end
    end

    # Takes a datagram that came from `from` with the ECN codepoint `ecn`.
    # The packets coalesced in it are handled one after another; nothing
    # the peer sends raises. While
    # closing, a datagram is answered with the CONNECTION_CLOSE frame again,
    # the first, second, fourth and so on; while draining, nothing.
    def receive(datagram, from:, to: nil, ecn: :not_ect, now:)
      @now = now
      case @state
      when :open then nil
      when :closing
        @closing_datagrams += 1
        @close_frame_due = true if (@closing_datagrams & (@closing_datagrams - 1)).zero?
        return
      else return
      end
      count_received(datagram, now) unless @address_validated
      processed = false
      offset = 0
      while offset < datagram.bytesize
        packet = parse_packet(datagram, offset, now) or break
        processed = true if receive_packet(packet, from:, ecn:, now:)
        offset = packet.end_offset
        break unless @state == :open
      end
      take_stateless_reset(datagram, now:) unless processed
    rescue Violation => error
      # What a packet that opened breaks closes the connection; only an
      # authenticated peer gets here, or one past the integrity limit (250
      # "Errors").
      close_for(error, now)
    end

    # RFC 9000 "Detecting a Stateless Reset": whether `datagram`, none of
    # whose packets this connection could take, ends in a stateless reset
    # token the peer gave, which the connection then drains on, sending
    # nothing more. Each token is compared in constant time.
    def take_stateless_reset(datagram, now:)
      return false unless @state == :open && StatelessReset.match?(datagram, @reset_tokens)
      enter_draining(ConnectionError.new(code: ErrorCode::NO_ERROR, frame_type: 0, reason: "stateless reset", application: false), now)
      true
    end

    # Each datagram there is to send now.
    def each_transmit(now:)
      @now = now
      while (datagram = next_datagram(now))
        yield Transmit.new(payload: datagram, destination: remote, source: nil, ecn: @path.ecn, segment_size: nil)
      end
    end

    def transmits(now:)
      transmits = [] #: Array[Transmit]
      each_transmit(now:) { |transmit| transmits << transmit }
      transmits
    end

    # When something is to be done next: a timer of loss recovery, the
    # idle timeout or the end of the previous 1-RTT keys while open, the end
    # of closing or draining after.
    def next_timeout
      case @state
      when :open
        # A server at its amplification limit cannot send an ACK either, so
        # an ACK's deadline would only come round again and again.
        [@amplification_limited ? @recovery.loss_detection_timer : @recovery.next_timeout, @idle_deadline,
          @protection.next_timeout].compact.min
      when :closing, :draining then @close_deadline
      end
    end

    def handle_timeout(now:)
      @now = now
      case @state
      when :open
        idle = @idle_deadline
        return time_out_idly if idle && now >= idle
        @protection.handle_timeout(now:)
        outcome = @recovery.on_timeout(now:)
        Recovery::Duty.dispatch(outcome, to: self)
        probe(outcome.probe) if outcome.probe
      when :closing, :draining
        deadline = @close_deadline
        @state = :closed if deadline && now >= deadline
      end
    end

    # TLSBinding::_Connection

    def install_keys(level, direction, secret:, suite:)
      @protection.install(level, direction, secret:, suite:)
      @recovery.handshake_keys_installed! if level == :handshake
    end

    # The peer's transport parameters: their connection IDs must be the ones
    # its Initial packets used, and its max_ack_delay and max_idle_timeout
    # count from now on.
    def peer_transport_parameters(data)
      parameters = TransportParameters.decode(data, sender: @role == :client ? :server : :client)
      authenticate_connection_ids(parameters)
      token = parameters.stateless_reset_token
      @reset_tokens << token if token
      @tracer.parameters_set(owner: :remote, parameters:, now: @now) if @tracer # steep:ignore
      @peer_parameters = parameters
      @streams.peer_parameters = parameters
      @recovery.peer_max_ack_delay = parameters.max_ack_delay
      restart_idle(@now)
    end

    # A server confirms the handshake as it completes, and tells the client
    # with HANDSHAKE_DONE.
    def handshake_completed(event)
      @handshake_complete = true
      @events << Event::Connected.new(handshake: event)
      return unless @role == :server
      @handshake_done_due = true
      confirm(@now)
    end

    # TLS failed and has forgotten its secrets: the connection closes with
    # `code`, a transport error of the CRYPTO frame.
    def tls_failed(code, reason)
      return unless @state == :open
      enter_closing(ConnectionError.new(code:, frame_type: CryptoStream::FRAME_TYPE, reason: reason.to_s, application: false), @now)
    end

    def tls_event(event) = @events << Event::TLSEvent.new(event:)

    # Recovery::Duty::_Owner

    def crypto_data_acked(duty) = binding.crypto_acked(duty)

    def crypto_data_lost(duty) = binding.crypto_lost(duty)

    def ack_frame_acked(duty) = @recovery.ack_frame_acknowledged(duty.space, largest: duty.largest)

    def stream_data_acked(duty) = @streams.stream_data_acked(duty)

    def stream_data_lost(duty) = @streams.stream_data_lost(duty)

    def reset_stream_acked(duty) = @streams.reset_stream_acked(duty)

    def reset_stream_lost(duty) = @streams.reset_stream_lost(duty)

    def stop_sending_lost(duty) = @streams.stop_sending_lost(duty)

    def max_data_lost(duty) = @streams.max_data_lost(duty)

    def max_stream_data_lost(duty) = @streams.max_stream_data_lost(duty)

    def data_blocked_lost(duty) = @streams.data_blocked_lost(duty)

    def stream_data_blocked_lost(duty) = @streams.stream_data_blocked_lost(duty)

    def streams_blocked_lost(duty) = @streams.streams_blocked_lost(duty)

    # Stream counts, connection IDs and tokens are not sent yet, so their
    # duties never come back.

    def max_streams_lost(duty) = nil
    def new_connection_id_lost(duty) = nil
    def retire_connection_id_lost(duty) = nil
    def new_token_lost(duty) = nil
    # RFC 9000 "Retransmission of Information": HANDSHAKE_DONE goes again
    # until it is acknowledged.
    def handshake_done_lost
      @handshake_done_due = true if @state == :open
    end

    private def remote = @remote || raise(Error::StateError, "no packet has come from the client yet")

    # A connection closing or closed takes no more from the application.
    private def open!
      raise Error::StateError, "the connection is #{@state}" unless @state == :open
    end

    private def binding = @binding || raise(Error::StateError, "no Initial packet has come from the client yet")

    # The 1-RTT keys changed to those of key phase `phase`.
    private def keys_updated(phase)
      @events << Event::KeyUpdated.new(phase:)
      @tracer.key_updated(level: :one_rtt, now: @now) if @tracer # steep:ignore
    end

    # The packet at `offset` in `datagram`, nil when there is none to take.
    # A header that does not read is dropped with the rest of the datagram
    # and nothing else: before its protection is off, anyone could have sent
    # it. So is a packet of a version not supported. A Retry or a Version
    # Negotiation packet, which fill the datagram, a client may take.
    private def parse_packet(datagram, offset, now)
      packet = Wire::Packet.parse(datagram, offset:, dcid_length: @source_connection_id.bytesize)
      case packet
      when Wire::Packet::Parsed then packet
      when Wire::Retry then take_retry(packet, datagram.bytesize - offset, now)
      when Wire::VersionNegotiation then take_version_negotiation(packet, datagram.bytesize - offset, now)
      else dropped(:unsupported, datagram.bytesize - offset, now)
      end
    rescue Wire::Malformed
      dropped(:invalid, datagram.bytesize - offset, now)
    end

    # RFC 9000 "Handling Version Negotiation Packets": a client of version 1
    # alone abandons the connection, sending nothing, on a Version
    # Negotiation that does not list its version, before it has taken any
    # other packet; one that echoes its connection IDs, as the server's has
    # to (RFC 9000 "Version Negotiation Packet"). Any other is dropped. Nil,
    # as the packet fills the datagram.
    private def take_version_negotiation(packet, length, now)
      unless @role == :client && @peer_source_connection_id.nil? && @retry_source_connection_id.nil? &&
          packet.dcid == @source_connection_id && packet.scid == @original_destination_connection_id &&
          !packet.versions.include?(@version.number)
        return dropped(:general, length, now)
      end
      reason = "the server takes none of the versions offered, but #{packet.versions.map { |version| format("0x%08x", version) }.join(", ")}"
      error = ConnectionError.new(code: ErrorCode::CONNECTION_REFUSED, frame_type: 0, reason:, application: false)
      @state = :closed
      @close_error = error
      @binding&.discard
      @events << Event::Closed.new(error:, by_peer: true)
      nil
    end

    # RFC 9000 "Retry Packet": a client takes one Retry, to its connection
    # ID, before any packet of the server has opened, with the tag of its
    # first Destination Connection ID and a Source Connection ID other than
    # that. Its Initials go from then on to that connection ID with the
    # Retry's token, under the Initial keys of it, and what they carried
    # goes again (RFC 9002 "Handling Retry"); the transport parameters of
    # the server must name the Retry's Source Connection ID. Nil, as the
    # Retry fills the datagram.
    private def take_retry(packet, length, now)
      odcid = @original_destination_connection_id
      unless @role == :client && @retry_source_connection_id.nil? && @peer_source_connection_id.nil? && odcid &&
          packet.dcid == @source_connection_id && packet.scid != @destination_connection_id && packet.authentic?(odcid)
        return dropped(:general, length, now)
      end
      @retry_source_connection_id = packet.scid
      @destination_connection_id = packet.scid
      @token = packet.token
      @protection.install_initial(packet.scid)
      Recovery::Duty.dispatch(@recovery.on_retry(now:), to: self)
      nil
    end

    # Tells the tracer that `length` bytes of packets were dropped for
    # `reason`, a trigger of qlog `packet_dropped`.
    private def dropped(reason, length, now)
      @tracer.packet_dropped(reason:, raw_length: length, now:) if @tracer # steep:ignore
      nil
    end

    private def receive_packet(packet, from:, ecn:, now:)
      header = packet.header
      level = header.type
      length = packet.end_offset - packet.offset
      if header.is_a?(Wire::LongHeader) && (id = @peer_source_connection_id) && header.scid != id
        return dropped(:connection_unknown, length, now)
      end
      # RFC 9000 "Datagram Size": a server drops an Initial packet in a
      # datagram under 1200 bytes.
      return dropped(:invalid, length, now) if @role == :server && level == :initial && packet.datagram.bytesize < MIN_INITIAL_DATAGRAM
      first = @role == :server && @binding.nil?
      keys = (first ? first_initial_keys(header) : @protection.read_keys(level)) or return dropped(:key_unavailable, length, now)
      unmasked = packet.unmask(keys.header_protection, largest: @recovery.largest_received(level))
      payload = (first ? unmasked.open(keys.aead) : @protection.open(level, unmasked, now:, pto: @path.rtt.pto_period))
      return dropped(:decryption_failure, length, now) unless payload
      accept_first_initial(header, from) if first && header.is_a?(Wire::LongHeader)
      frames = Wire::Frame.parse(payload, packet_type: level, ack_delay_exponent: peer_ack_delay_exponent(level))
      processed = @recovery.on_packet_received(packet_type: level, packet_number: unmasked.packet_number, ecn:,
        ack_eliciting: frames.any?(&:ack_eliciting?), now:)
      return dropped(:duplicate, length, now) unless processed
      if @tracer
        @tracer.packet_received(header: Tracer::PacketHeader.of(unmasked.header, unmasked.packet_number), # steep:ignore
          frames: @tracer.trace_frames? ? frames : nil, raw_length: length, now:) # steep:ignore
      end
      # RFC 9000 "Idle Timeout": a packet received and processed, which a
      # duplicate is not.
      restart_idle(now)
      @eliciting_since_received = false
      adopt_peer_connection_id(header) if @role == :client && header.is_a?(Wire::LongHeader) && level == :initial
      frames.each { |frame| receive_frame(level, frame, now) }
      if @role == :server && level == :handshake
        validate_address(now)
        discard_level(:initial, now)
      end
      true
    end

    # RFC 9000 "Authenticating Connection IDs": the connection IDs the peer
    # names in its transport parameters are those of the Initial packets,
    # and a Retry's when there was one, or the connection fails with
    # TRANSPORT_PARAMETER_ERROR.
    private def authenticate_connection_ids(parameters)
      wrong = [] #: Array[Symbol]
      wrong << :initial_source_connection_id unless parameters.initial_source_connection_id == @peer_source_connection_id
      if @role == :client
        wrong << :original_destination_connection_id unless parameters.original_destination_connection_id == @original_destination_connection_id
        wrong << :retry_source_connection_id unless parameters.retry_source_connection_id == @retry_source_connection_id
      end
      return if wrong.empty?
      raise Violation.new("#{wrong.join(" and ")} not as the packets had it", code: ErrorCode::TRANSPORT_PARAMETER_ERROR,
        frame_type: CryptoStream::FRAME_TYPE)
    end

    # The keys a client's first Initial is sealed with, from its own
    # Destination Connection ID; nil for any other packet.
    private def first_initial_keys(header)
      return nil unless header.is_a?(Wire::LongHeader) && header.type == :initial
      Crypto::Initial.derive(dcid: header.dcid, version: @version).client
    end

    # The server learns from the client's first Initial, once it has opened,
    # its connection ID, address and the Destination Connection ID its
    # Initial keys come from. Until then anyone could have sent it.
    private def accept_first_initial(header, from)
      @remote = from
      @destination_connection_id = header.scid
      @peer_source_connection_id = header.scid
      @protection.install_initial(header.dcid)
      @original_destination_connection_id ||= header.dcid
      parameters = @config.transport_parameters(initial_source_connection_id: @source_connection_id,
        original_destination_connection_id: @original_destination_connection_id, retry_source_connection_id: @retry_source_connection_id,
        stateless_reset_token: @stateless_reset_token)
      @tracer.parameters_set(owner: :local, parameters:, now: @now) if @tracer # steep:ignore
      @binding = @start_binding.call(self, parameters)
    end

    # A client takes the Source Connection ID of the server's first Initial
    # packet as the Destination Connection ID of its own, and only that one
    # (RFC 9000 "Negotiating Connection IDs").
    private def adopt_peer_connection_id(header)
      return if @peer_source_connection_id
      @destination_connection_id = header.scid
      @peer_source_connection_id = header.scid
    end

    private def receive_frame(level, frame, now)
      return unless @state == :open
      case frame
      when Wire::Frame::Crypto then binding.receive_crypto(level, frame, time: tls_time(now))
      when Wire::Frame::Ack
        Recovery::Duty.dispatch(@recovery.on_ack_received(packet_type: level, ack: frame, now:), to: self)
        @protection.acknowledged(frame.largest) if level == :one_rtt
      when Wire::Frame::ConnectionClose
        enter_draining(ConnectionError.new(code: frame.code, frame_type: frame.frame_type, reason: frame.reason, application: frame.application), now)
      when Wire::Frame::HandshakeDone
        raise Violation.new("HANDSHAKE_DONE from a client", frame_type: 0x1e) if @role == :server
        confirm(now)
      when Wire::Frame::Stream then @streams.receive_stream(frame, now:)
      when Wire::Frame::MaxData then @streams.receive_max_data(frame)
      when Wire::Frame::MaxStreamData then @streams.receive_max_stream_data(frame, now:)
      when Wire::Frame::MaxStreams then @streams.receive_max_streams(frame)
      when Wire::Frame::DataBlocked then @streams.receive_data_blocked(frame)
      when Wire::Frame::StreamDataBlocked then @streams.receive_stream_data_blocked(frame, now:)
      when Wire::Frame::ResetStream then @streams.receive_reset_stream(frame, now:)
      when Wire::Frame::StopSending then @streams.receive_stop_sending(frame, now:)
      end
    end

    # RFC 9001 "Discarding Handshake Keys": once the handshake is
    # confirmed, the Handshake keys go, and loss recovery counts Application
    # Data.
    private def confirm(now)
      return if @handshake_confirmed
      @handshake_confirmed = true
      @recovery.handshake_confirmed!(now:)
      @protection.handshake_confirmed!
      discard_level(:handshake, now)
    end

    # RFC 9000 "Immediate Close": what was being sent stops, and only the
    # CONNECTION_CLOSE frame goes, as soon as it can.
    private def enter_closing(error, now)
      @state = :closing
      @close_error = error
      @close_deadline = now + CLOSE_PTOS * @path.rtt.pto_period
      @close_frame_due = true
      @binding&.discard
      @events << Event::Closed.new(error:, by_peer: false)
    end

    private def close_for(violation, now)
      error = ConnectionError.new(code: violation.code, frame_type: violation.frame_type || 0, reason: violation.message, application: false)
      enter_closing(error, now)
    end

    # The peer closed: nothing more is sent, and what comes is dropped for
    # three PTOs (RFC 9000 "Draining Connection State").
    private def enter_draining(error, now)
      @state = :draining
      @close_error = error
      @close_deadline = now + CLOSE_PTOS * @path.rtt.pto_period
      @binding&.discard
      @events << Event::Closed.new(error:, by_peer: true)
    end

    # RFC 9000 "Idle Timeout": the connection ends at once, with nothing
    # sent.
    private def time_out_idly
      error = ConnectionError.new(code: ErrorCode::NO_ERROR, frame_type: 0, reason: "idle timeout", application: false)
      @state = :closed
      @close_error = error
      @binding&.discard
      @events << Event::Closed.new(error:, by_peer: false)
    end

    # The idle timeout starts again from `now`: the smaller of the two ends'
    # max_idle_timeout, 0 being none, and three PTOs at least.
    private def restart_idle(now)
      timeouts = [@config.max_idle_timeout, @peer_parameters&.max_idle_timeout].compact.reject(&:zero?)
      timeout = timeouts.min
      @idle_deadline = timeout && now + [timeout, CLOSE_PTOS * @path.rtt.pto_period].max
    end

    # The next datagram to send, nil when there is nothing. What elicits an
    # ACK goes only while the congestion window has room for a datagram
    # more, or a probe is due. The 1-RTT keys change first when a key update
    # is due; when they cannot and are at their confidentiality limit, the
    # connection closes. While closing, only the CONNECTION_CLOSE frame, when
    # due. When nothing goes, the path hears why.
    private def next_datagram(now)
      return closing_datagram(now) unless @state == :open
      limit = @path.max_datagram_size
      limit = [limit, amplification_budget(now)].min unless @address_validated
      return stopped(:amplification) if limit < MIN_INITIAL_DATAGRAM
      eliciting = @path.bytes_in_flight + limit <= @path.congestion.window || @probes.values.any?(&:positive?)
      begin
        @protection.update_keys_if_due
      rescue Violation => error
        close_for(error, now)
        return closing_datagram(now)
      end
      pending = [] #: Array[Pending]
      used = 0
      LEVELS.each do |level|
        next unless @protection.can_write?(level)
        header = header_for(level)
        room = limit - used - overhead(header)
        frames, duties = frames_for(level, room, eliciting, now)
        next if frames.empty?
        packet_number = @recovery.next_packet_number(level)
        length = @recovery.packet_number_length(level, packet_number)
        pending << Pending.new(level:, header:, packet_number:, packet_number_length: length, frames:, duties:)
        used += overhead(header) + Wire::Frame.encode(frames, ack_delay_exponent: own_ack_delay_exponent(level)).bytesize
      end
      return stopped(eliciting ? :drained : :congestion) if pending.empty?
      datagram = seal(pending, now)
      @sent_unvalidated += datagram.bytesize unless @address_validated
      discard_level(:initial, now) if @role == :client && pending.any? { |packet| packet.level == :handshake }
      datagram
    end

    # Sending stops for `reason`: the path keeps whether the congestion
    # window went unused, which loss recovery tells the congestion
    # controller (RFC 9002 "Underutilizing the Congestion Window"). With
    # the window too full for a datagram more, what is left waits on it.
    private def stopped(reason)
      @path.transmission_stopped(reason)
      nil
    end

    # How many bytes a server may still send before the client's address is
    # validated. Under a datagram's worth, it stops, and loss recovery sets no
    # timer meanwhile (RFC 9002 "Handling Anti-Amplification Limits").
    private def amplification_budget(now)
      budget = AMPLIFICATION_FACTOR * @received_unvalidated - @sent_unvalidated
      if budget < MIN_INITIAL_DATAGRAM && !@amplification_limited
        @amplification_limited = true
        @recovery.amplification_limited(true, now:)
      end
      budget
    end

    private def count_received(datagram, now)
      @received_unvalidated += datagram.bytesize
      return unless @amplification_limited
      return if AMPLIFICATION_FACTOR * @received_unvalidated - @sent_unvalidated < MIN_INITIAL_DATAGRAM
      @amplification_limited = false
      @recovery.amplification_limited(false, now:)
    end

    # A Handshake packet from the client proves its address.
    private def validate_address(now)
      return if @address_validated
      @address_validated = true
      return unless @amplification_limited
      @amplification_limited = false
      @recovery.amplification_limited(false, now:)
    end

    # A PTO asks for `probe.packets` packets that elicit an ACK in
    # `probe.space`.
    private def probe(probe)
      @probes[probe.space] = @probes.fetch(probe.space, 0) + probe.packets
    end

    # A probe of `level` carries what is new when there is some, else the
    # duties of the oldest packet in flight again, its record left as it is,
    # else a PING (loss recovery's design, "Probes").
    private def fill_probe(level)
      return if binding.crypto_pending?(level) || (level == :one_rtt && @handshake_done_due)
      oldest = @recovery.oldest_ack_eliciting(SPACES.fetch(level)) or return
      Recovery::Duty.dispatch(Recovery::Outcome.new(acked: Recovery::Outcome::NO_PACKETS, lost: [oldest], probe: nil), to: self)
    end

    # RFC 9001 "Discarding Unused Keys": the keys of `level`, its CRYPTO
    # stream and what was sent in it go, once. A client's Initial keys go when
    # it first sends a Handshake packet, a server's when it first processes
    # one.
    private def discard_level(level, now)
      return if @protection.discarded?(level)
      @probes.delete(SPACES.fetch(level))
      @protection.discard(level)
      binding.discard_level(level)
      @recovery.discard_space(level, now:)
    end

    # The CONNECTION_CLOSE frame in a packet of each level there are keys to
    # write, since the peer may not have all of them yet (RFC 9000 "Immediate
    # Close during the Handshake").
    private def closing_datagram(now)
      return nil unless @state == :closing && @close_frame_due
      return nil unless @address_validated || amplification_budget(now) >= MIN_INITIAL_DATAGRAM
      @close_frame_due = false
      pending = CLOSE_LEVELS.filter_map do |level|
        next unless @protection.can_write?(level)
        packet_number = @recovery.next_packet_number(level)
        Pending.new(level:, header: header_for(level), packet_number:, packet_number_length: @recovery.packet_number_length(level, packet_number),
          frames: [close_frame(level)], duties: [])
      end
      return nil if pending.empty?
      datagram = seal(pending, now)
      @sent_unvalidated += datagram.bytesize unless @address_validated
      datagram
    end

    # An application's error closes with APPLICATION_ERROR and no reason in
    # Initial and Handshake packets, where only a transport error may go.
    private def close_frame(level)
      error = @close_error or raise Error::StateError, "the connection is not closing"
      reason = error.reason.b.byteslice(0, MAX_REASON_LENGTH) #: String
      if error.application && level != :one_rtt
        Wire::Frame::ConnectionClose.new(code: ErrorCode::APPLICATION_ERROR, frame_type: 0, reason: "".b, application: false)
      else
        Wire::Frame::ConnectionClose.new(code: error.code, frame_type: error.application ? nil : error.frame_type || 0, reason:,
          application: error.application)
      end
    end

    # The frames of `level` that fit in `room` bytes, and their duties: an
    # ACK when one is owed and the packet goes anyway, or is due, then, when
    # frames that elicit an ACK may go, HANDSHAKE_DONE and CRYPTO, credit,
    # RESET_STREAM and STOP_SENDING, BLOCKED frames, stream data, and a PING
    # for a probe with nothing else.
    private def frames_for(level, room, eliciting, now)
      frames = [] #: Array[Wire::Frame::t]
      duties = [] #: Array[Recovery::Duty::t]
      space = SPACES.fetch(level)
      ack = @recovery.ack_frame(space, now:) if @recovery.ack_owed?(space) || @recovery.ack_due?(space, now:)
      room -= Wire::Frame.encode([ack], ack_delay_exponent: own_ack_delay_exponent(level)).bytesize if ack
      fill_probe(level) if eliciting && @probes.fetch(space, 0).positive?
      if eliciting && level == :one_rtt && @handshake_done_due && room.positive?
        @handshake_done_due = false
        frames << Wire::Frame::HandshakeDone.new
        duties << Recovery::Duty::HandshakeDone.new
        room -= 1
      end
      while eliciting && room.positive? && (frame, duty = binding.next_crypto_frame(level, room))
        frames << frame
        duties << duty
        room -= Wire::Frame.encode([frame], ack_delay_exponent: 0).bytesize
      end
      while eliciting && level == :one_rtt && (credit, credit_duty = @streams.next_credit(room, now:, rtt: rtt_sample))
        frames << credit
        duties << credit_duty
        room -= Wire::Frame.encode([credit], ack_delay_exponent: 0).bytesize
      end
      while eliciting && level == :one_rtt && (abandon, abandon_duty = @streams.next_abandon(room))
        frames << abandon
        duties << abandon_duty
        room -= Wire::Frame.encode([abandon], ack_delay_exponent: 0).bytesize
      end
      while eliciting && level == :one_rtt && (blocked, blocked_duty = @streams.next_blocked(room))
        frames << blocked
        duties << blocked_duty
        room -= Wire::Frame.encode([blocked], ack_delay_exponent: 0).bytesize
      end
      while eliciting && level == :one_rtt && room.positive? && (data, data_duty = @streams.next_stream_frame(room))
        frames << data
        duties << data_duty
        room -= Wire::Frame.encode([data], ack_delay_exponent: 0).bytesize
      end
      if eliciting && @probes.fetch(space, 0).positive? && frames.none?(&:ack_eliciting?) && room.positive?
        frames << Wire::Frame::Ping.new
        room -= 1
      end
      if ack && (frames.any? || @recovery.ack_due?(space, now:))
        frames.unshift(ack)
        duties.unshift(Recovery::Duty::Ack.new(space:, largest: ack.largest))
        @recovery.on_ack_sent(space, now:)
      end
      [frames, duties]
    end

    # Protects the packets of a datagram and records them as sent. The
    # last is padded to make the datagram MIN_INITIAL_DATAGRAM bytes when
    # it carries a client's Initial, or a server's that elicits an ACK, and
    # every packet so that header protection has its sample.
    private def seal(pending, now)
      target = pending.any? { |packet| padded_initial?(packet) } ? MIN_INITIAL_DATAGRAM : 0
      payloads = pending.map do |packet|
        payload = Wire::Frame.encode(packet.frames, ack_delay_exponent: own_ack_delay_exponent(packet.level))
        short = Wire::Packet::SAMPLE_OFFSET - packet.packet_number_length - payload.bytesize
        short.positive? ? payload + "\0".b * short : payload
      end
      size = pending.each_with_index.sum { |packet, index| sealed_size(packet, payloads.fetch(index).bytesize) }
      payloads[-1] = padded(pending.fetch(-1), payloads.fetch(-1), target - size) if target > size
      pending.each_with_index.map { |packet, index| protect(packet, payloads.fetch(index), now) }.join
    end

    # RFC 9000 "Datagram Size": every Initial of a client, and those of a
    # server that elicit an ACK, go in datagrams of 1200 bytes at least.
    private def padded_initial?(packet)
      packet.level == :initial && (@role == :client || packet.frames.any?(&:ack_eliciting?))
    end

    # `payload` with `missing` bytes of PADDING, less what the Length field
    # grows by.
    private def padded(packet, payload, missing)
      grown = sealed_size(packet, payload.bytesize + missing) - sealed_size(packet, payload.bytesize) - missing
      payload + "\0".b * (missing - grown)
    end

    private def protect(packet, payload, now)
      keys = @protection.write_keys(packet.level) or raise Error::StateError, "no keys to write #{packet.level}"
      sealed = Wire::Packet.seal(packet.header, packet_number: packet.packet_number, packet_number_length: packet.packet_number_length,
        payload:, keys:)
      if packet.level == :one_rtt
        acknowledging = packet.frames.filter_map { |frame| frame.largest if frame.is_a?(Wire::Frame::Ack) }.first
        @protection.sent(packet.packet_number, acknowledging:)
      end
      if @tracer
        @tracer.packet_sent(header: Tracer::PacketHeader.of(packet.header, packet.packet_number), # steep:ignore
          frames: @tracer.trace_frames? ? packet.frames : nil, raw_length: sealed.bytesize, now:) # steep:ignore
      end
      ack_eliciting = packet.frames.any?(&:ack_eliciting?)
      in_flight = ack_eliciting || payload.bytesize > Wire::Frame.encode(packet.frames, ack_delay_exponent: 0).bytesize
      if ack_eliciting && !@eliciting_since_received
        @eliciting_since_received = true
        restart_idle(now)
      end
      space = SPACES.fetch(packet.level)
      @probes[space] = @probes.fetch(space, 0) - 1 if ack_eliciting && @probes.fetch(space, 0).positive?
      @recovery.on_packet_sent(packet_type: packet.level, packet_number: packet.packet_number, sent_bytes: sealed.bytesize,
        ack_eliciting:, in_flight:, duties: packet.duties, now:)
      sealed
    end

    private def header_for(level)
      case level
      when :one_rtt then Wire::ShortHeader.new(dcid: @destination_connection_id, key_phase: @protection.key_phase_bit)
      when :initial
        Wire::LongHeader.new(type: level, version: @version, dcid: @destination_connection_id, scid: @source_connection_id, token: @token)
      else Wire::LongHeader.new(type: level, version: @version, dcid: @destination_connection_id, scid: @source_connection_id)
      end
    end

    private def overhead(header)
      case header
      when Wire::LongHeader then LONG_HEADER_OVERHEAD + header.dcid.bytesize + header.scid.bytesize + token_field(header)
      else SHORT_HEADER_OVERHEAD + header.dcid.bytesize
      end
    end

    # The Token Length and Token fields, which only an Initial packet has.
    private def token_field(header) = header.type == :initial ? Wire::Varint.size(header.token.bytesize) + header.token.bytesize : 0

    # The bytes of `packet` with a payload of `length` bytes, protected.
    private def sealed_size(packet, length)
      header = packet.header
      keys = @protection.write_keys(packet.level) or raise Error::StateError, "no keys to write #{packet.level}"
      body = packet.packet_number_length + length + keys.aead.tag_length
      case header
      when Wire::LongHeader
        1 + 4 + 1 + header.dcid.bytesize + 1 + header.scid.bytesize + token_field(header) + Wire::Varint.size(body) + body
      else 1 + header.dcid.bytesize + body
      end
    end

    private def own_ack_delay_exponent(level) = level == :one_rtt ? @config.ack_delay_exponent : DEFAULT_ACK_DELAY_EXPONENT

    private def peer_ack_delay_exponent(level)
      return DEFAULT_ACK_DELAY_EXPONENT unless level == :one_rtt
      @peer_parameters&.ack_delay_exponent || DEFAULT_ACK_DELAY_EXPONENT
    end

    # The path's smoothed RTT, nil before its first sample.
    private def rtt_sample = @path.rtt.first_sample_at && @path.rtt.smoothed_rtt

    # TLS's wall clock at `now`.
    private def tls_time(now) = @time + (now - @created_at)
  end
end
