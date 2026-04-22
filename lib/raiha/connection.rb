# frozen_string_literal: true

require "securerandom"
require_relative "stream"
require_relative "streams_map"
require_relative "quic/protocol"
require_relative "quic/wire/frame_parser"
require_relative "quic/wire/long_header"
require_relative "quic/wire/short_header"
require_relative "quic/handshake/encryption_level"
require_relative "quic/handshake/crypto_setup"
require_relative "quic/handshake/tls_adapter"
require_relative "quic/handshake/transport_parameters"
require_relative "quic/wire/buffer"
require_relative "quic/ack_handler"
require_relative "quic/congestion"
require_relative "quic/flow_control"
require_relative "quic/timer"
require_relative "quic/stateless_reset"
require_relative "quic/wire/version_negotiation"
require_relative "quic/qerr/error_code"
require_relative "quic/qerr/transport_error"
require_relative "qlog"

module Raiha
  class Connection
    module State
      HANDSHAKING = :handshaking
      CONNECTED = :connected
      # CLOSING: we sent CONNECTION_CLOSE and may re-send it in response to
      # incoming packets (RFC 9000 §10.2.1). Transitions to CLOSED when the
      # drain timer expires.
      CLOSING = :closing
      # DRAINING: we received CONNECTION_CLOSE from the peer and must not
      # send any more packets (RFC 9000 §10.2.2).
      DRAINING = :draining
      CLOSED = :closed
    end

    attr_reader :perspective
    attr_reader :src_connection_id
    attr_reader :dest_connection_id
    attr_reader :state
    attr_reader :streams
    attr_reader :qlog_writer
    # Most recent address-validation token (NEW_TOKEN, RFC 9000 §19.7)
    # issued by the peer. Clients persist this across sessions to present
    # it in the token field of the next Initial packet.
    attr_reader :peer_issued_token
    # Versions the server advertised if it sent a Version Negotiation
    # packet (RFC 9000 §6). Populated on clients when the handshake is
    # abandoned because no version matched; nil otherwise.
    attr_reader :peer_supported_versions

    def initialize(perspective:, src_connection_id:, dest_connection_id:, transport_parameters: nil, tls_config: nil, server_name: nil, alpn_protocols: nil)
      @perspective = Quic::Protocol::Perspective.coerce(perspective)
      @src_connection_id = src_connection_id
      @dest_connection_id = dest_connection_id
      @state = State::HANDSHAKING
      @transport_parameters = transport_parameters || Quic::Handshake::TransportParameters.new
      @tls_config = tls_config
      @server_name = server_name
      @alpn_protocols = alpn_protocols

      @transport_parameters.initial_source_connection_id = @src_connection_id.serialize

      setup_components
    end

    def handle_frames(frames, level: Quic::Handshake::EncryptionLevel::INITIAL)
      frames.each do |frame|
        case frame
        when Quic::Wire::Frames::AckFrame
          handle_ack_frame(frame, level: level)
        when Quic::Wire::Frames::CryptoFrame
          handle_crypto_frame(frame, level: level)
        when Quic::Wire::Frames::StreamFrame
          handle_stream_frame(frame)
        when Quic::Wire::Frames::MaxDataFrame
          @connection_flow_controller.update_send_window(frame.maximum_data)
        when Quic::Wire::Frames::MaxStreamDataFrame
          handle_max_stream_data_frame(frame)
        when Quic::Wire::Frames::MaxStreamsFrame
          if frame.bidirectional
            @streams.update_peer_max_streams_bidi(frame.maximum_streams)
          else
            @streams.update_peer_max_streams_uni(frame.maximum_streams)
          end
        when Quic::Wire::Frames::ConnectionCloseFrame
          enter_draining_state
        when Quic::Wire::Frames::HandshakeDoneFrame
          complete_handshake if @state == State::HANDSHAKING
        when Quic::Wire::Frames::PathChallengeFrame
          queue_path_response(frame.data)
        when Quic::Wire::Frames::PathResponseFrame
          handle_path_response(frame.data)
        when Quic::Wire::Frames::NewConnectionIdFrame
          handle_new_connection_id(frame)
        when Quic::Wire::Frames::RetireConnectionIdFrame
          handle_retire_connection_id(frame)
        when Quic::Wire::Frames::ResetStreamFrame
          handle_reset_stream_frame(frame)
        when Quic::Wire::Frames::StopSendingFrame
          handle_stop_sending_frame(frame)
        when Quic::Wire::Frames::NewTokenFrame
          handle_new_token_frame(frame)
        end
      end

      reset_idle_timer
    end

    def open_stream(bidirectional: true)
      if bidirectional
        @streams.open_bidirectional_stream
      else
        @streams.open_unidirectional_stream
      end
    end

    def accept_stream
      @streams.accept_stream
    end

    def accept_stream_nonblock
      @streams.accept_stream_nonblock
    end

    def enable_qlog(output:, title: nil)
      @qlog_writer = Qlog::Writer.new(output: output, title: title)
      @qlog_writer.start_trace(
        vantage_point: @perspective,
        connection_id: @src_connection_id.serialize.unpack1("H*")
      )
      log_event(Qlog::ConnectionEvents::ConnectionStarted.new(
        src_cid: @src_connection_id.serialize.unpack1("H*"),
        dest_cid: @dest_connection_id.serialize.unpack1("H*")
      ))
    end

    def flush_qlog
      @qlog_writer&.flush
    end

    # Start the handshake (client-initiated)
    def start_handshake
      @tls_adapter.start
    end

    # Application-driven close with an implicit NO_ERROR (RFC 9000 §20.1).
    # Sends CONNECTION_CLOSE with a transport-level code; use
    # #close_with_application_error for application-level codes.
    def close(error_code: 0, reason: "")
      close_with_error(error_code: error_code, reason_phrase: reason)
    end

    # Send a transport-level CONNECTION_CLOSE (type 0x1c) and enter the
    # closing state. `frame_type` is the QUIC frame type that triggered
    # the close when applicable (RFC 9000 §19.19), or nil.
    def close_with_error(error_code:, reason_phrase: "", frame_type: nil)
      frame = Quic::Wire::Frames::ConnectionCloseFrame.new
      frame.error_code = error_code
      frame.trigger_frame_type = frame_type || 0
      frame.reason_phrase = reason_phrase
      frame.application_error = false
      enter_closing_state(frame)
    end

    # Send an application-level CONNECTION_CLOSE (type 0x1d).
    def close_with_application_error(error_code:, reason_phrase: "")
      frame = Quic::Wire::Frames::ConnectionCloseFrame.new
      frame.error_code = error_code
      frame.reason_phrase = reason_phrase
      frame.application_error = true
      enter_closing_state(frame)
    end

    # Minimum Initial packet size per RFC 9000 Section 14.1
    MIN_INITIAL_PACKET_SIZE = 1200

    # Build a QUIC packet containing the given frames at the specified encryption level
    def build_packet(frames, level:, pad_to_min: false)
      return nil if frames.empty?

      packet_number = @sent_packet_handler.get_next_packet_number(level_to_pn_space(level))

      # Serialize frames
      frame_buf = Quic::Wire::Buffer.new
      frames.each { |frame| frame_buf.write(frame.serialize) }
      payload = frame_buf.to_s

      # Encode packet number
      encoded_packet_number = encode_packet_number(packet_number.value)

      # For Initial packets from client, pad to minimum size
      should_pad = pad_to_min || (level == Quic::Handshake::EncryptionLevel::INITIAL && @perspective.client?)
      if should_pad
        header_bytes_estimate = build_header(level, encoded_packet_number, 0)
        overhead = header_bytes_estimate.bytesize + encoded_packet_number.bytesize + 16 # AEAD tag
        padding_needed = MIN_INITIAL_PACKET_SIZE - overhead - payload.bytesize
        if padding_needed > 0
          padding_frame = Quic::Wire::Frames::PaddingFrame.new
          payload += padding_frame.serialize * padding_needed
        end
      end

      # Build header with actual payload size
      header_bytes = build_header(level, encoded_packet_number, payload.bytesize)

      # AAD = header bytes including packet number
      aad = header_bytes + encoded_packet_number

      # Encrypt payload
      encrypted = @crypto_setup.encrypt(payload, packet_number: packet_number.value, aad: aad, level: level)

      # Assemble packet (before header protection)
      raw_packet = aad + encrypted

      # Apply header protection
      apply_header_protection(raw_packet, header_bytes.bytesize, encoded_packet_number.bytesize, level)

      # Track sent packet
      @sent_packet_handler.sent_packet(
        packet_number: packet_number,
        frames: frames,
        size: raw_packet.bytesize,
        ack_eliciting: frames.any?(&:ack_eliciting?),
        pn_space: level_to_pn_space(level)
      )

      log_packet_sent(level: level, packet_number: packet_number.value, frames: frames)

      raw_packet
    end

    # Build an Initial packet with CRYPTO frame containing TLS data
    def build_initial_packet(crypto_data)
      frames = [] #: Array[Quic::Wire::Frame]
      frames << Quic::Wire::Frames::CryptoFrame.new.tap do |frame|
        frame.offset = 0
        frame.data = crypto_data
      end

      build_packet(frames, level: Quic::Handshake::EncryptionLevel::INITIAL)
    end

    # Build the UDP datagrams ready to go out. Each returned string is a
    # complete datagram that the caller writes to its socket; a datagram
    # may carry multiple QUIC packets coalesced together (RFC 9000 §12.2),
    # with at most one packet per encryption level and the short-header
    # 1-RTT packet always last.
    def get_packets_to_send
      return [] if @state == State::CLOSED
      # RFC 9000 §10.2.2: draining endpoints MUST NOT send anything.
      return [] if @state == State::DRAINING
      # RFC 9000 §10.2.1: closing endpoints emit only CONNECTION_CLOSE.
      return emit_connection_close if @state == State::CLOSING

      datagrams = [] #: Array[String]

      initial_packet = build_level_packet(Quic::Handshake::EncryptionLevel::INITIAL)
      handshake_packet = build_level_packet(Quic::Handshake::EncryptionLevel::HANDSHAKE)
      one_rtt_packet = build_level_packet(Quic::Handshake::EncryptionLevel::ONE_RTT)

      datagram = String.new(encoding: "BINARY")
      datagram << initial_packet if initial_packet
      datagram << handshake_packet if handshake_packet
      datagram << one_rtt_packet if one_rtt_packet

      emit_datagram(datagrams, datagram) unless datagram.empty?

      datagrams
    end

    private def emit_connection_close
      datagrams = [] #: Array[String]
      return datagrams unless @pending_close_frame
      return datagrams unless @close_frame

      level = best_available_level_for_close
      return datagrams unless level

      packet = build_packet([@close_frame], level: level)
      @pending_close_frame = false
      emit_datagram(datagrams, packet) if packet
      datagrams
    end

    private def best_available_level_for_close
      [Quic::Handshake::EncryptionLevel::ONE_RTT,
       Quic::Handshake::EncryptionLevel::HANDSHAKE,
       Quic::Handshake::EncryptionLevel::INITIAL].find { |level| @crypto_setup.available?(level) }
    end

    # Gather every frame queued for `level` and build a single packet
    # holding all of them. Returns nil if no keys are installed for the
    # level or nothing is pending.
    private def build_level_packet(level)
      return nil unless @crypto_setup.available?(level)

      frames = gather_frames_for(level)
      return nil if frames.empty?

      build_packet(frames, level: level)
    end

    private def gather_frames_for(level)
      frames = [] #: Array[Quic::Wire::Frame]

      ack_frame = pending_ack_frame(level)
      frames << ack_frame if ack_frame

      # Drain every pending CRYPTO payload for this level so a single packet
      # carries them all at their distinct, contiguous offsets (RFC 9000
      # §19.6).
      while (chunk = @crypto_setup.pop_crypto_frame(level: level))
        crypto_frame = Quic::Wire::Frames::CryptoFrame.new
        crypto_frame.offset = chunk[:offset]
        crypto_frame.data = chunk[:data]
        frames << crypto_frame
      end

      return frames unless level == Quic::Handshake::EncryptionLevel::ONE_RTT

      # 1-RTT carries every application-level frame type we emit.
      gather_one_rtt_frames(frames)
      frames
    end

    private def gather_one_rtt_frames(frames)
      if @pending_stream_frames
        frames.concat(@pending_stream_frames)
        @pending_stream_frames = [] #: Array[Quic::Wire::Frames::StreamFrame]
      end

      append_flow_control_frames(frames)

      if @pending_path_responses
        frames.concat(@pending_path_responses)
        @pending_path_responses = [] #: Array[Quic::Wire::Frames::PathResponseFrame]
      end

      frames.concat(@pending_path_challenges)
      @pending_path_challenges = [] #: Array[Quic::Wire::Frames::PathChallengeFrame]

      @pending_retire_connection_ids.each do |sequence_number|
        retire = Quic::Wire::Frames::RetireConnectionIdFrame.new
        retire.sequence_number = sequence_number
        frames << retire
      end
      @pending_retire_connection_ids = [] #: Array[Integer]

      @streams.each_stream do |stream|
        reset_frame = stream.take_reset_stream_frame
        frames << reset_frame if reset_frame
        stop_frame = stream.take_stop_sending_frame
        frames << stop_frame if stop_frame
      end

      if @pending_ping_frames
        frames.concat(@pending_ping_frames)
        @pending_ping_frames = [] #: Array[Quic::Wire::Frames::PingFrame]
      end

      if @pending_handshake_done
        frames << Quic::Wire::Frames::HandshakeDoneFrame.new
        @pending_handshake_done = false
      end

      if @pending_new_tokens
        @pending_new_tokens.each do |token|
          nt = Quic::Wire::Frames::NewTokenFrame.new
          nt.token = token
          frames << nt
        end
        @pending_new_tokens = [] #: Array[String]
      end
    end

    private def append_flow_control_frames(frames)
      if @connection_flow_controller.should_send_window_update?
        new_limit = @connection_flow_controller.get_window_update
        md = Quic::Wire::Frames::MaxDataFrame.new
        md.maximum_data = new_limit
        frames << md
      end

      @streams.each_stream do |stream|
        fc = stream.flow_controller
        next unless fc.should_send_window_update?

        new_limit = fc.get_window_update
        msd = Quic::Wire::Frames::MaxStreamDataFrame.new
        msd.stream_id = stream.stream_id.value
        msd.maximum_stream_data = new_limit
        frames << msd
      end

      # Flip side: signal to the peer when we have data to send but flow
      # control is holding us back (RFC 9000 §19.12 / §19.13). The limit
      # value is whatever send_window value capped us.
      if @connection_flow_controller.pending_blocked_signal?
        db = Quic::Wire::Frames::DataBlockedFrame.new
        db.maximum_data = @connection_flow_controller.take_blocked_signal
        frames << db
      end

      @streams.each_stream do |stream|
        fc = stream.flow_controller
        next unless fc.pending_blocked_signal?

        sdb = Quic::Wire::Frames::StreamDataBlockedFrame.new
        sdb.stream_id = stream.stream_id.value
        sdb.maximum_stream_data = fc.take_blocked_signal
        frames << sdb
      end

      # STREAMS_BLOCKED (RFC 9000 §19.14): we tried to open a new stream
      # but the peer's max_streams limit stopped us.
      limits = @streams.stream_limit_controller
      if limits.pending_bidi_blocked_signal?
        sb = Quic::Wire::Frames::StreamsBlockedFrame.new
        sb.bidirectional = true
        sb.maximum_streams = limits.take_bidi_blocked_signal
        frames << sb
      end
      if limits.pending_uni_blocked_signal?
        sb = Quic::Wire::Frames::StreamsBlockedFrame.new
        sb.bidirectional = false
        sb.maximum_streams = limits.take_uni_blocked_signal
        frames << sb
      end
    end

    # Peer-supplied alternate connection IDs we may route to (RFC 9000 §5.1).
    # Each entry is a hash with :sequence_number, :connection_id,
    # and :stateless_reset_token keys.
    def peer_connection_ids
      @peer_connection_ids.dup
    end

    # Send a PATH_CHALLENGE with 8 bytes of fresh random data (RFC 9000 §8.2.1).
    # The data is tracked in @outstanding_path_challenges; a matching
    # PATH_RESPONSE from the peer validates the current path and flips
    # peer_path_validated? to true. Returns the challenge bytes so the caller
    # can correlate it if needed.
    def initiate_path_validation
      data = SecureRandom.random_bytes(8)
      challenge = Quic::Wire::Frames::PathChallengeFrame.new
      challenge.data = data
      @pending_path_challenges << challenge
      @outstanding_path_challenges << data
      data
    end

    def peer_path_validated?
      @peer_path_validated
    end

    # Accepts a built datagram into the outgoing list if the server's
    # anti-amplification budget permits (RFC 9000 §8.1): prior to address
    # validation, cumulative bytes sent MUST NOT exceed 3x bytes received.
    # Dropped datagrams are discarded here; their frames were already
    # drained from the pending queues, so loss detection will rebuild
    # them on the next ACK or PTO.
    private def emit_datagram(datagrams, datagram)
      return if datagram.empty?

      if @perspective.server? && !@address_validated
        budget = 3 * @bytes_received_from_peer - @bytes_sent_to_peer
        return if datagram.bytesize > budget
      end

      datagrams << datagram
      @bytes_sent_to_peer += datagram.bytesize
    end

    # Queue a PATH_RESPONSE carrying the 8-byte challenge received from the peer.
    private def queue_path_response(challenge_data)
      response = Quic::Wire::Frames::PathResponseFrame.new
      response.data = challenge_data

      @pending_path_responses ||= [] #: Array[Quic::Wire::Frames::PathResponseFrame]
      @pending_path_responses << response
    end

    # Match a received PATH_RESPONSE against our outstanding challenges.
    # RFC 9000 §8.2.3: a response with non-matching data is a
    # PROTOCOL_VIOLATION; a matching response validates the current path.
    # When the matched challenge was sent as part of a migration probe,
    # RFC 9000 §9.4 additionally requires resetting the congestion
    # controller and RTT estimator so the new path starts from scratch.
    private def handle_path_response(response_data)
      unless @outstanding_path_challenges.delete(response_data)
        close_with_error(
          error_code: Quic::Qerr::TransportErrorCode::PROTOCOL_VIOLATION,
          reason_phrase: "PATH_RESPONSE did not match any outstanding PATH_CHALLENGE",
          frame_type: Quic::Wire::Frame::Type::PATH_RESPONSE
        )
        return
      end

      @peer_path_validated = true

      if @migration_challenges.delete(response_data)
        @congestion_controller.reset if @congestion_controller.respond_to?(:reset)
        @rtt_stats.reset if @rtt_stats.respond_to?(:reset)
      end
    end

    # Track a new alternate connection ID issued by the peer. When
    # retire_prior_to is non-zero, every known entry with a smaller sequence
    # number MUST be retired (RFC 9000 §5.1.2) by sending
    # RETIRE_CONNECTION_ID back.
    private def handle_new_connection_id(frame)
      # RFC 9000 §19.15: a duplicate sequence number with the same CID and
      # stateless reset token is a plain retransmission; one carrying a
      # different CID or token is a PROTOCOL_VIOLATION.
      existing = @peer_connection_ids.find { |entry| entry[:sequence_number] == frame.sequence_number }
      if existing && (existing[:connection_id] != frame.connection_id ||
                      existing[:stateless_reset_token] != frame.stateless_reset_token)
        raise Quic::Qerr::ProtocolViolation.new(
          frame_type: Quic::Wire::Frame::Type::NEW_CONNECTION_ID,
          reason_phrase: "NEW_CONNECTION_ID reuses sequence number with different CID or token"
        )
      end
      return if existing

      @peer_connection_ids << {
        sequence_number: frame.sequence_number,
        connection_id: frame.connection_id,
        stateless_reset_token: frame.stateless_reset_token,
      }

      return unless frame.retire_prior_to.positive?

      @peer_connection_ids.reject! do |entry|
        if entry[:sequence_number] < frame.retire_prior_to
          @pending_retire_connection_ids << entry[:sequence_number]
          true
        end
      end
    end

    # The peer is informing us that a connection ID we issued has been
    # retired. We only ever advertise @src_connection_id today, so there is
    # no CID pool to prune here. Recording the frame still matters: it
    # removes the dispatch from the "silently dropped" category and leaves a
    # hook for a future CID-rotation feature.
    private def handle_retire_connection_id(_frame)
      # TODO: when we start issuing additional source connection IDs via
      # NEW_CONNECTION_ID, retire the matching entry and generate a
      # replacement.
    end

    # Returns an AckFrame for the given encryption level, or nil if none needed
    private def pending_ack_frame(level)
      pn_space = level_to_pn_space(level)
      return nil unless @received_packet_handler.should_send_ack?(pn_space)

      @received_packet_handler.get_ack_frame(pn_space)
    end

    # Queue stream data for sending as a 1-RTT STREAM frame
    def send_stream_data(stream_id, data, offset: 0, fin: false)
      stream_id_value = stream_id.is_a?(Integer) ? stream_id : stream_id.value
      sid = Quic::Protocol::StreamID.new(stream_id_value)
      unless sid.writable_by?(@perspective)
        raise ArgumentError, "stream #{stream_id_value} is not writable by this endpoint"
      end

      stream_frame = Quic::Wire::Frames::StreamFrame.new
      stream_frame.stream_id = stream_id_value
      stream_frame.offset = offset
      stream_frame.data = data
      stream_frame.fin = fin

      @pending_stream_frames ||= [] #: Array[Quic::Wire::Frames::StreamFrame]
      @pending_stream_frames << stream_frame
    end

    # Earliest wall-clock deadline at which this connection has something to
    # do without receiving new network input — the application should
    # schedule a call to `tick` at or before this time. Returns nil if no
    # timer is armed.
    def next_timer_deadline
      candidates = [
        @sent_packet_handler.loss_detection_deadline,
        @idle_timer.deadline,
        @drain_timer&.deadline,
      ].compact #: Array[Time]
      return nil if candidates.empty?

      candidates.min
    end

    # Drive timer-based work: time-threshold loss detection, idle-timeout
    # silent close (RFC 9000 §10.1), and draining timeout (§10.2.2).
    # Callers should invoke this whenever next_timer_deadline has passed
    # (or earlier). Takes an explicit `now` for deterministic testing.
    def tick(now: Time.now)
      return if @state == State::CLOSED

      loss_deadline = @sent_packet_handler.loss_detection_deadline
      if loss_deadline && loss_deadline <= now
        @sent_packet_handler.on_loss_detection_timeout(now: now)
      end

      drain_deadline = @drain_timer&.deadline
      if drain_deadline && drain_deadline <= now
        enter_closed_state
        return
      end

      # Closing / draining state is governed by drain_timer, not idle_timer.
      return if @state == State::DRAINING || @state == State::CLOSING

      idle_deadline = @idle_timer.deadline
      if idle_deadline && idle_deadline <= now
        enter_closed_state
      end
    end

    # Issue an address-validation token to the peer (RFC 9000 §8.1.3,
    # §19.7). The server calls this with an opaque byte string that a
    # future client can replay in the token field of its Initial packet;
    # this library does not prescribe the token format, so the caller is
    # responsible for generating and later validating it.
    def send_new_token(token)
      raise Raiha::Error, "NEW_TOKEN may only be sent by the server" unless @perspective.server?

      @pending_new_tokens ||= [] #: Array[String]
      @pending_new_tokens << token
    end

    # Application-driven send-side reset (RFC 9000 §3.5).
    def reset_stream(stream_id, error_code)
      stream = @streams.get_stream(stream_id)
      return unless stream

      stream.reset(error_code)
    end

    # Application-driven STOP_SENDING: ask the peer to stop sending on this
    # stream (RFC 9000 §3.5, §19.5).
    def stop_sending(stream_id, error_code)
      stream = @streams.get_stream(stream_id)
      return unless stream

      stream.stop_sending(error_code)
    end

    # RFC 9002 §6.3.1: frames carried in a lost packet that were not already
    # acknowledged or superseded need to be retransmitted. Called from
    # SentPacketHandler when the packet threshold declares a loss.
    private def on_packet_lost(packet, pn_space)
      level = pn_space_to_level(pn_space)
      packet.frames.each { |frame| requeue_lost_frame(frame, level: level) }
    end

    private def pn_space_to_level(pn_space)
      case pn_space
      when Quic::Protocol::PacketNumberSpace::INITIAL
        Quic::Handshake::EncryptionLevel::INITIAL
      when Quic::Protocol::PacketNumberSpace::HANDSHAKE
        Quic::Handshake::EncryptionLevel::HANDSHAKE
      else
        Quic::Handshake::EncryptionLevel::ONE_RTT
      end
    end

    # RFC 9002 §6.2.4: on PTO expiry, emit one ack-eliciting probe packet to
    # provoke a fresh ACK from the peer. A PING frame is always sufficient
    # and doesn't conflict with pending application data.
    private def on_pto_fired
      @pending_ping_frames ||= [] #: Array[Quic::Wire::Frames::PingFrame]
      @pending_ping_frames << Quic::Wire::Frames::PingFrame.new
    end

    private def requeue_lost_frame(frame, level:)
      case frame
      when Quic::Wire::Frames::StreamFrame
        @pending_stream_frames ||= [] #: Array[Quic::Wire::Frames::StreamFrame]
        @pending_stream_frames << frame
      when Quic::Wire::Frames::CryptoFrame
        @crypto_setup.requeue_crypto_data(offset: frame.offset, data: frame.data, level: level)
      when Quic::Wire::Frames::ResetStreamFrame
        stream = @streams.get_stream(frame.stream_id)
        stream&.requeue_reset_stream_frame
      when Quic::Wire::Frames::StopSendingFrame
        stream = @streams.get_stream(frame.stream_id)
        stream&.requeue_stop_sending_frame
      when Quic::Wire::Frames::RetireConnectionIdFrame
        @pending_retire_connection_ids << frame.sequence_number
      when Quic::Wire::Frames::HandshakeDoneFrame
        @pending_handshake_done = true
      when Quic::Wire::Frames::NewTokenFrame
        @pending_new_tokens ||= [] #: Array[String]
        @pending_new_tokens << frame.token
      # ACK / PADDING / PATH_CHALLENGE / PATH_RESPONSE / PING /
      # MAX_* / CONNECTION_CLOSE aren't retransmitted here: ACK and
      # PADDING are never retransmitted; PATH_RESPONSE is replaced by a
      # fresh PATH_CHALLENGE round if the peer still needs validation;
      # MAX_* frames are self-healing because they always carry the
      # latest limit and re-emit on the next window-update check;
      # PING is produced fresh by PTO firings, so a lost PING would be
      # replaced by the next PTO.
      end
    end

    # RFC 9000 §9: record the current peer address and, if the handshake
    # is complete and it changes, probe the new path. The actual PATH
    # routing belongs to the caller (socket layer); Connection merely
    # queues a PATH_CHALLENGE that the caller sends on the new 4-tuple.
    private def observe_peer_address(peer_address)
      if @peer_address.nil?
        @peer_address = peer_address
        return
      end

      return if @peer_address == peer_address

      @peer_address = peer_address
      @migration_count += 1

      # Migration is only defined post-handshake (§9.2). Before that, a
      # changing 4-tuple is expected (client's first Initial can be
      # followed by retransmits from other ephemeral ports) and
      # handle_packet just trusts the caller.
      return unless @state == State::CONNECTED

      # Re-validate the new path. On receipt of the matching
      # PATH_RESPONSE, @peer_path_validated flips true again and the §9.4
      # reset fires (see handle_path_response).
      @peer_path_validated = false
      challenge = initiate_path_validation
      @migration_challenges << challenge
    end

    def migration_count
      @migration_count
    end

    private def handle_version_negotiation(data)
      parsed = Quic::Wire::VersionNegotiation.parse(data)
      return unless parsed

      # If the server listed a version we already agreed to speak, RFC
      # §6.2 says we MUST treat it as a protocol violation (the server is
      # advertising a version it already accepted). For raiha, which has
      # no version-fallback mechanism yet, we abandon unconditionally.
      @peer_supported_versions = parsed[:supported_versions]
      enter_closed_state
    end

    private def handle_new_token_frame(frame)
      # RFC 9000 §19.7: a server that receives NEW_TOKEN MUST treat it as a
      # PROTOCOL_VIOLATION; NEW_TOKEN is server-only.
      unless @perspective.client?
        close_with_error(
          error_code: Quic::Qerr::TransportErrorCode::PROTOCOL_VIOLATION,
          reason_phrase: "server received NEW_TOKEN",
          frame_type: Quic::Wire::Frame::Type::NEW_TOKEN
        )
        return
      end

      @peer_issued_token = frame.token
    end

    # RFC 9000 §19.10: MAX_STREAM_DATA flows receiver→sender. The peer sends
    # it when they are the receiver on this stream, so we must be the sender.
    # A receive-only stream from our perspective is a STREAM_STATE_ERROR.
    private def handle_max_stream_data_frame(frame)
      stream_id = Quic::Protocol::StreamID.new(frame.stream_id)
      unless stream_id.writable_by?(@perspective)
        raise Quic::Qerr::StreamStateError.new(
          frame_type: Quic::Wire::Frame::Type::MAX_STREAM_DATA,
          reason_phrase: "MAX_STREAM_DATA for a receive-only stream"
        )
      end

      @streams.get_stream(frame.stream_id)&.update_send_window(frame.maximum_stream_data)
    end

    private def handle_reset_stream_frame(frame)
      # RFC 9000 §3.5: RESET_STREAM flows sender→receiver. Receiving it on a
      # stream where we are the sender (a locally-initiated unidirectional
      # stream) is a STREAM_STATE_ERROR.
      stream_id = Quic::Protocol::StreamID.new(frame.stream_id)
      unless stream_id.readable_by?(@perspective)
        raise Quic::Qerr::StreamStateError.new(
          frame_type: Quic::Wire::Frame::Type::RESET_STREAM,
          reason_phrase: "RESET_STREAM on a locally-initiated unidirectional stream"
        )
      end

      stream = @streams.get_or_create_stream(frame.stream_id)
      stream.handle_reset_stream(
        error_code: frame.application_protocol_error_code,
        final_size: frame.final_size
      )
    end

    private def handle_stop_sending_frame(frame)
      # RFC 9000 §3.5: STOP_SENDING flows receiver→sender. The peer sends it
      # when they are the receiver on this stream, so we must be the sender
      # — a peer-initiated unidirectional stream (where peer is sender) is
      # a STREAM_STATE_ERROR.
      stream_id = Quic::Protocol::StreamID.new(frame.stream_id)
      unless stream_id.writable_by?(@perspective)
        raise Quic::Qerr::StreamStateError.new(
          frame_type: Quic::Wire::Frame::Type::STOP_SENDING,
          reason_phrase: "STOP_SENDING on a peer-initiated unidirectional stream"
        )
      end

      stream = @streams.get_stream(frame.stream_id)

      # RFC 9000 §19.5: STOP_SENDING targeting a locally-initiated stream
      # we have not yet opened is STREAM_STATE_ERROR.
      if stream.nil? && stream_id.initiator == @perspective
        raise Quic::Qerr::StreamStateError.new(
          frame_type: Quic::Wire::Frame::Type::STOP_SENDING,
          reason_phrase: "STOP_SENDING for a locally-initiated stream that has not been created"
        )
      end
      return unless stream

      stream.handle_stop_sending(frame.application_protocol_error_code)
    end

    def complete_handshake
      old_state = @state
      @state = State::CONNECTED
      # RFC 9000 §8.1.2: completing the handshake implicitly validates the
      # peer's address, so the 3x anti-amplification limit is lifted.
      @address_validated = true
      log_state_updated(old_state: old_state, new_state: @state)
      apply_peer_transport_parameters

      # RFC 9000 §19.20: the server MUST signal handshake completion with a
      # HANDSHAKE_DONE frame, which is the client's cue to discard Initial
      # and Handshake keys.
      queue_handshake_done if @perspective.server?
    end

    private def queue_handshake_done
      @pending_handshake_done = true
    end

    private def apply_peer_transport_parameters
      peer_tp = @tls_adapter.peer_transport_parameters
      return unless peer_tp

      peer_tp.validate_peer!

      @streams.update_peer_max_streams_bidi(peer_tp.initial_max_streams_bidi) if peer_tp.initial_max_streams_bidi
      @streams.update_peer_max_streams_uni(peer_tp.initial_max_streams_uni) if peer_tp.initial_max_streams_uni
      @connection_flow_controller.update_send_window(peer_tp.initial_max_data) if peer_tp.initial_max_data

      # RFC 9000 §18.2: stateless_reset_token advertises a token for the
      # connection ID the peer used during the handshake, separate from
      # any token delivered later via NEW_CONNECTION_ID.
      @peer_transport_reset_token = peer_tp.stateless_reset_token
    end

    private def known_peer_reset_tokens
      tokens = @peer_connection_ids.map { |entry| entry[:stateless_reset_token] }.compact
      tokens << @peer_transport_reset_token if @peer_transport_reset_token
      tokens
    end

    def handshake_complete?
      @state == State::CONNECTED
    end

    def closed?
      @state == State::CLOSED
    end

    def draining?
      @state == State::DRAINING
    end

    def closing?
      @state == State::CLOSING
    end

    # Reassembles CRYPTO frame data arriving at different offsets.
    # Only returns data when complete TLS handshake messages are available.
    class CryptoStreamBuffer
      def initialize
        @buffer = String.new(encoding: "BINARY")
        @write_end = 0
        @read_offset = 0
      end

      def push(offset, data)
        end_pos = offset + data.bytesize
        if end_pos > @buffer.bytesize
          @buffer << ("\x00" * (end_pos - @buffer.bytesize))
        end
        @buffer[offset, data.bytesize] = data
        @write_end = [@write_end, end_pos].max
      end

      # Returns complete TLS handshake messages from the read offset, or nil if incomplete
      def read
        available = @buffer[@read_offset, @write_end - @read_offset]
        return nil if available.nil? || available.bytesize < 4

        # Try to read complete handshake messages (type[1] + length[3] + body[length])
        result = String.new(encoding: "BINARY")
        pos = 0
        while pos + 4 <= available.bytesize
          message_length = ("\x00" + available[pos + 1, 3]).unpack1("N")
          total_length = 4 + message_length
          break if pos + total_length > available.bytesize

          result << available[pos, total_length]
          pos += total_length
        end

        return nil if result.empty?

        @read_offset += pos
        result
      end
    end

    private def setup_components
      @rtt_stats = Quic::Congestion::RTTStats.new(
        max_ack_delay: @transport_parameters.max_ack_delay / 1000.0
      )

      @congestion_controller = Quic::Congestion::Cubic.new(rtt_stats: @rtt_stats)

      @sent_packet_handler = Quic::AckHandler::SentPacketHandler.new(
        congestion_controller: @congestion_controller,
        rtt_stats: @rtt_stats,
        on_packet_lost: method(:on_packet_lost),
        on_pto_fired: method(:on_pto_fired)
      )

      @received_packet_handler = Quic::AckHandler::ReceivedPacketHandler.new

      @connection_flow_controller = Quic::FlowControl::ConnectionFlowController.new(
        receive_window: @transport_parameters.initial_max_data,
        send_window: 0
      )

      @streams = StreamsMap.new(
        perspective: @perspective,
        connection_flow_controller: @connection_flow_controller,
        max_streams_bidi: @transport_parameters.initial_max_streams_bidi,
        max_streams_uni: @transport_parameters.initial_max_streams_uni
      )

      @crypto_setup = Quic::Handshake::CryptoSetup.new(
        perspective: @perspective,
        connection_id: @dest_connection_id
      )

      @tls_adapter = Quic::Handshake::TLSAdapter.new(
        perspective: @perspective,
        crypto_setup: @crypto_setup,
        tls_config: @tls_config,
        server_name: @server_name,
        transport_parameters: @transport_parameters,
        alpn_protocols: @alpn_protocols
      )

      @crypto_stream_buffers = {} #: Hash[Symbol, untyped]

      # RFC 9000 §8.1: until the peer's address is validated, the server MUST
      # NOT send more than three times the bytes it has received. These two
      # counters plus @address_validated enforce that limit in get_packets_to_send.
      @bytes_received_from_peer = 0
      @bytes_sent_to_peer = 0
      @address_validated = false

      # RFC 9000 §8.2: path validation. Endpoints may initiate a PATH_CHALLENGE
      # and track outstanding 8-byte challenges until a matching PATH_RESPONSE
      # comes back.
      @pending_path_challenges = [] #: Array[Quic::Wire::Frames::PathChallengeFrame]
      @outstanding_path_challenges = [] #: Array[String]
      @peer_path_validated = false

      # RFC 9000 §5.1: alternate connection IDs the peer has issued to us,
      # plus a queue of sequence numbers for which we still owe the peer a
      # RETIRE_CONNECTION_ID frame.
      @peer_connection_ids = [] #: Array[Hash[Symbol, untyped]]
      @pending_retire_connection_ids = [] #: Array[Integer]

      # RFC 9000 §9: peer address tracking for migration detection. The
      # current address is opaque to Connection (caller supplies it via
      # handle_packet(peer_address:)) but a change after the handshake
      # completes auto-triggers a PATH_CHALLENGE so the caller can route
      # the validation exchange itself.
      @peer_address = nil #: untyped
      @migration_count = 0
      # Outstanding PATH_CHALLENGE data we sent as part of a migration
      # probe. A matching PATH_RESPONSE triggers §9.4 cwnd/RTT reset.
      @migration_challenges = [] #: Array[String]

      @idle_timer = Quic::Timer.new
      reset_idle_timer
    end

    # Process a raw QUIC packet (with header protection and encryption).
    # A single UDP datagram may contain multiple coalesced QUIC packets
    # (RFC 9000 §12.2). `ecn` is the IP-layer ECN mark observed on the
    # datagram (:not_ect / :ect0 / :ect1 / :ce) for §13.4 ECN feedback;
    # the caller is responsible for reading it from the socket via
    # recvmsg / IPV6_RECVTCLASS. Defaults to :not_ect when absent.
    # `peer_address` is the opaque identifier (e.g. [ip, port]) of the
    # sender. When provided and it differs from the previously observed
    # one after the handshake completes, path validation is initiated
    # automatically (RFC 9000 §9).
    def handle_packet(data, ecn: :not_ect, peer_address: nil)
      return if @state == State::CLOSED
      return if @state == State::DRAINING

      # RFC 9000 §10.3.1: check the final 16 bytes of the datagram against
      # any stateless reset tokens the peer has advertised. A match means
      # the peer has lost connection state and is asking us to abandon it
      # immediately — enter draining and stop processing.
      if Quic::StatelessReset.match_token?(data, known_peer_reset_tokens)
        enter_draining_state
        return
      end

      # RFC 9000 §6.2: a client receiving a Version Negotiation packet MUST
      # abandon the connection attempt. Record the list of versions the
      # server did advertise so the application can decide whether to
      # retry with a different version.
      if @perspective.client? && Quic::Wire::VersionNegotiation.match?(data)
        handle_version_negotiation(data)
        return
      end

      @bytes_received_from_peer += data.bytesize

      # RFC 9000 §10.2.1: every datagram received while closing prompts us
      # to re-send CONNECTION_CLOSE. The frame is otherwise dropped.
      if @state == State::CLOSING
        @pending_close_frame = true
        return
      end

      observe_peer_address(peer_address) if peer_address

      offset = 0
      while offset < data.bytesize
        remaining = data[offset..]
        first_byte = remaining.getbyte(0)

        # RFC 9000 Section 17.2/17.3: the Fixed Bit (bit 6) MUST be 1 for both Long
        # and Short Header packets. A first byte below 0x40 is datagram-level padding
        # (some implementations pad coalesced datagrams with zero bytes to 1200).
        break if first_byte < 0x40

        if (first_byte & 0x80) != 0
          consumed = handle_long_header_packet(remaining, Quic::Wire::Buffer.new(remaining), ecn: ecn)
          break unless consumed && consumed > 0
          offset += consumed
        else
          handle_short_header_packet(remaining, Quic::Wire::Buffer.new(remaining), ecn: ecn)
          break # Short header packets are always last in a coalesced datagram
        end
      end
    rescue Quic::Qerr::TransportError => error
      # RFC 9000 §11: a transport-level protocol violation detected during
      # packet processing becomes an outgoing CONNECTION_CLOSE.
      enter_closing_state(error.to_connection_close_frame)
    rescue => error
      # Log error but don't crash the connection
      $stderr.puts "Connection error handling packet: #{error.class}: #{error.message}" if $DEBUG
    end

    # Returns the number of bytes consumed, or nil on failure
    private def handle_long_header_packet(data, buffer, ecn: :not_ect)
      header = Quic::Wire::LongHeader.parse(buffer)

      level = case header.packet_type
      when Quic::Wire::LongHeader::PacketType::INITIAL
        Quic::Handshake::EncryptionLevel::INITIAL
      when Quic::Wire::LongHeader::PacketType::HANDSHAKE
        Quic::Handshake::EncryptionLevel::HANDSHAKE
      when Quic::Wire::LongHeader::PacketType::ZERO_RTT
        Quic::Handshake::EncryptionLevel::ZERO_RTT
      else
        return nil
      end

      update_connection_ids_from_initial(header) if level == Quic::Handshake::EncryptionLevel::INITIAL

      # Packet number starts at current buffer position
      packet_number_offset = buffer.pos

      # Total packet size: header + payload_length (which includes PN + encrypted data)
      total_packet_size = packet_number_offset + header.payload_length

      return nil unless @crypto_setup.available?(level)

      # Remove header protection (RFC 9001 Section 5.4.2)
      # Sample is 4 bytes after the start of the packet number field
      sample_offset = packet_number_offset + 4
      return nil if sample_offset + 16 > data.bytesize

      sample = data[sample_offset, 16]
      mask = @crypto_setup.header_protection_mask(sample, level: level, direction: :receive)

      # Make a mutable copy of the data for unmasking
      unprotected_data = data.dup

      # Unmask first byte to get packet number length
      if unprotected_data.getbyte(0) & 0x80 != 0
        unprotected_data.setbyte(0, unprotected_data.getbyte(0) ^ (mask.getbyte(0) & 0x0f))
      else
        unprotected_data.setbyte(0, unprotected_data.getbyte(0) ^ (mask.getbyte(0) & 0x1f))
      end

      packet_number_length = (unprotected_data.getbyte(0) & 0x03) + 1

      # Unmask packet number bytes
      packet_number_length.times do |i|
        offset = packet_number_offset + i
        unprotected_data.setbyte(offset, unprotected_data.getbyte(offset) ^ mask.getbyte(1 + i))
      end

      # Read packet number from unprotected data
      packet_number_bytes = unprotected_data[packet_number_offset, packet_number_length]
      packet_number = decode_packet_number(packet_number_bytes)

      # AAD is the unprotected header including packet number
      aad = unprotected_data[0, packet_number_offset + packet_number_length]

      # Encrypted payload starts after packet number
      encrypted_payload_offset = packet_number_offset + packet_number_length
      encrypted_payload_length = header.payload_length - packet_number_length
      encrypted_payload = data[encrypted_payload_offset, encrypted_payload_length]

      begin
        decrypted = @crypto_setup.decrypt(encrypted_payload, packet_number: packet_number, aad: aad, level: level)
        frames = Quic::Wire::FrameParser.parse(Quic::Wire::Buffer.new(decrypted))
        log_packet_received(level: level, packet_number: packet_number, frames: frames)
        @received_packet_handler.received_packet(
          packet_number: packet_number,
          pn_space: level_to_pn_space(level),
          ack_eliciting: frames.any?(&:ack_eliciting?),
          ecn: ecn
        )
        handle_frames(frames, level: level)
      rescue OpenSSL::Cipher::CipherError
        log_packet_dropped(level: level, trigger: :decryption_failure)
      end

      total_packet_size
    end

    private def handle_short_header_packet(data, buffer, ecn: :not_ect)
      connection_id_length = @src_connection_id.length
      level = Quic::Handshake::EncryptionLevel::ONE_RTT

      return unless @crypto_setup.available?(level)
      # 1: first byte, connection_id_length: DCID, 1: minimum packet number, 16: AEAD tag
      return if data.bytesize < 1 + connection_id_length + 1 + 16

      # Packet number starts after first byte and Destination Connection ID
      packet_number_offset = 1 + connection_id_length

      # Sample is 4 bytes after the start of the packet number field (RFC 9001 Section 5.4.2)
      sample_offset = packet_number_offset + 4
      return if sample_offset + 16 > data.bytesize

      sample = data[sample_offset, 16]
      mask = @crypto_setup.header_protection_mask(sample, level: level, direction: :receive)

      unprotected_data = data.dup

      # Short header uses 0x1f mask for first byte
      unprotected_data.setbyte(0, unprotected_data.getbyte(0) ^ (mask.getbyte(0) & 0x1f))

      packet_number_length = (unprotected_data.getbyte(0) & 0x03) + 1

      packet_number_length.times do |i|
        offset = packet_number_offset + i
        unprotected_data.setbyte(offset, unprotected_data.getbyte(offset) ^ mask.getbyte(1 + i))
      end

      packet_number_bytes = unprotected_data[packet_number_offset, packet_number_length]
      packet_number = decode_packet_number(packet_number_bytes)

      aad = unprotected_data[0, packet_number_offset + packet_number_length]

      encrypted_payload = data[(packet_number_offset + packet_number_length)..]

      begin
        decrypted = @crypto_setup.decrypt(encrypted_payload, packet_number: packet_number, aad: aad, level: level)
        frames = Quic::Wire::FrameParser.parse(Quic::Wire::Buffer.new(decrypted))
        log_packet_received(level: level, packet_number: packet_number, frames: frames)
        @received_packet_handler.received_packet(
          packet_number: packet_number,
          pn_space: level_to_pn_space(level),
          ack_eliciting: frames.any?(&:ack_eliciting?),
          ecn: ecn
        )
        handle_frames(frames, level: level)
      rescue OpenSSL::Cipher::CipherError
        log_packet_dropped(level: level, trigger: :decryption_failure)
      end
    end

    # Update connection IDs when receiving the first Initial packet from the peer.
    private def update_connection_ids_from_initial(header)
      if @perspective.client? && header.source_connection_id
        # RFC 9000 Section 7.2: client updates DCID to server's SCID
        @dest_connection_id = header.source_connection_id
      elsif @perspective.server? && !@initial_keys_rederived
        @dest_connection_id = header.source_connection_id if header.source_connection_id
        # RFC 9000 Section 7.3: record original DCID for transport parameters validation
        @transport_parameters.original_destination_connection_id = header.destination_connection_id.serialize
        # RFC 9001 Section 5.2: derive Initial keys from client's chosen DCID
        @crypto_setup.rederive_initial_keys(connection_id: header.destination_connection_id)
        @initial_keys_rederived = true
      end
    end

    private def decode_packet_number(bytes)
      case bytes.bytesize
      when 1 then bytes.unpack1("C")
      when 2 then bytes.unpack1("n")
      when 3 then ("\x00" + bytes).unpack1("N")
      when 4 then bytes.unpack1("N")
      else 0
      end
    end

    # RFC 9000 §19.3: ACK frames apply to the packet number space of the
    # packet they arrived in. The frame's Ack Delay field is encoded in
    # microseconds scaled by the peer's ack_delay_exponent transport
    # parameter (default 3, i.e. 8 microsecond units).
    private def handle_ack_frame(frame, level: Quic::Handshake::EncryptionLevel::ONE_RTT)
      ack_delay_seconds = decode_ack_delay(frame.ack_delay)
      @sent_packet_handler.received_ack(
        frame,
        pn_space: level_to_pn_space(level),
        ack_delay: ack_delay_seconds
      )
    end

    private def decode_ack_delay(encoded)
      peer_exponent = @tls_adapter.peer_transport_parameters&.ack_delay_exponent || 3
      (encoded << peer_exponent) / 1_000_000.0
    end

    private def handle_crypto_frame(frame, level: Quic::Handshake::EncryptionLevel::INITIAL)
      @crypto_stream_buffers[level] ||= CryptoStreamBuffer.new
      buffer = @crypto_stream_buffers[level]
      buffer.push(frame.offset, frame.data)

      data = buffer.read
      return unless data

      @tls_adapter.receive_crypto_data(data, level: level)

      if @tls_adapter.handshake_complete? && @state == State::HANDSHAKING
        complete_handshake
      end
    end

    private def handle_stream_frame(frame)
      # RFC 9000 §3.5: STREAM frames flow sender→receiver, so a STREAM frame
      # from the peer on a locally-initiated unidirectional stream (one we
      # can only send on) is a STREAM_STATE_ERROR.
      stream_id = Quic::Protocol::StreamID.new(frame.stream_id)
      unless stream_id.readable_by?(@perspective)
        raise Quic::Qerr::StreamStateError.new(
          frame_type: Quic::Wire::Frame::Type::STREAM.first,
          reason_phrase: "STREAM frame on a locally-initiated unidirectional stream"
        )
      end

      stream = @streams.get_or_create_stream(frame.stream_id)
      stream.receive_data(frame.offset, frame.data, fin: frame.fin)
    end

    private def enter_draining_state
      return if @state == State::DRAINING || @state == State::CLOSED

      old_state = @state
      @state = State::DRAINING
      log_state_updated(old_state: old_state, new_state: @state)

      drain_timeout = 3 * @rtt_stats.pto
      @drain_timer = Quic::Timer.new
      @drain_timer.set(drain_timeout)
    end

    private def enter_closing_state(close_frame)
      # Idempotent: a second close() call with an error keeps the first
      # frame; DRAINING / CLOSED short-circuit.
      return if @state == State::CLOSING || @state == State::DRAINING || @state == State::CLOSED

      old_state = @state
      @state = State::CLOSING
      @close_frame = close_frame
      @pending_close_frame = true
      log_state_updated(old_state: old_state, new_state: @state)

      drain_timeout = 3 * @rtt_stats.pto
      @drain_timer = Quic::Timer.new
      @drain_timer.set(drain_timeout)
    end

    private def enter_closed_state
      return if @state == State::CLOSED

      old_state = @state
      @state = State::CLOSED
      log_state_updated(old_state: old_state, new_state: @state)
    end

    private def reset_idle_timer
      timeout = @transport_parameters.max_idle_timeout / 1000.0
      @idle_timer.set(timeout) if timeout > 0
    end

    private def build_header(level, encoded_packet_number, payload_length)
      case level
      when Quic::Handshake::EncryptionLevel::INITIAL
        build_initial_header(encoded_packet_number, payload_length)
      when Quic::Handshake::EncryptionLevel::HANDSHAKE
        build_handshake_header(encoded_packet_number, payload_length)
      when Quic::Handshake::EncryptionLevel::ONE_RTT
        build_short_header(encoded_packet_number)
      end
    end

    private def build_initial_header(encoded_packet_number, payload_length)
      buf = Quic::Wire::Buffer.new

      # First byte: Long header (0x80) | Fixed bit (0x40) | Initial (0x00) | PN length
      first_byte = 0xc0 | ((encoded_packet_number.bytesize - 1) & 0x03)
      buf.write_uint8(first_byte)

      # Version
      buf.write_uint32(Quic::Protocol::Version::V1)

      # Destination Connection ID
      buf.write_uint8(@dest_connection_id.length)
      buf.write(@dest_connection_id.serialize)

      # Source Connection ID
      buf.write_uint8(@src_connection_id.length)
      buf.write(@src_connection_id.serialize)

      # Token (empty for client Initial)
      buf.write_varint(0)

      # Length (packet number + encrypted payload + AEAD tag)
      total_length = encoded_packet_number.bytesize + payload_length + 16 # 16 = AEAD tag
      buf.write_varint(total_length)

      buf.to_s
    end

    private def build_handshake_header(encoded_packet_number, payload_length)
      buf = Quic::Wire::Buffer.new

      # First byte: Long header (0x80) | Fixed bit (0x40) | Handshake (0x20) | PN length
      first_byte = 0xc0 | (0x02 << 4) | ((encoded_packet_number.bytesize - 1) & 0x03)
      buf.write_uint8(first_byte)

      buf.write_uint32(Quic::Protocol::Version::V1)

      buf.write_uint8(@dest_connection_id.length)
      buf.write(@dest_connection_id.serialize)
      buf.write_uint8(@src_connection_id.length)
      buf.write(@src_connection_id.serialize)

      total_length = encoded_packet_number.bytesize + payload_length + 16
      buf.write_varint(total_length)

      buf.to_s
    end

    private def build_short_header(encoded_packet_number)
      buf = Quic::Wire::Buffer.new

      # First byte: Fixed bit (0x40) | PN length
      first_byte = 0x40 | ((encoded_packet_number.bytesize - 1) & 0x03)
      buf.write_uint8(first_byte)

      buf.write(@dest_connection_id.serialize)

      buf.to_s
    end

    private def encode_packet_number(packet_number)
      if packet_number < 0x100
        [packet_number].pack("C")
      elsif packet_number < 0x10000
        [packet_number].pack("n")
      else
        [packet_number].pack("N")
      end
    end

    private def apply_header_protection(packet, header_length, packet_number_length, level)
      # Sample starts 4 bytes after the packet number
      sample_offset = header_length + 4
      return packet if sample_offset + 16 > packet.bytesize

      sample = packet[sample_offset, 16]
      mask = @crypto_setup.header_protection_mask(sample, level: level, direction: :send)

      # Mask first byte
      if packet.getbyte(0) & 0x80 != 0
        packet.setbyte(0, packet.getbyte(0) ^ (mask.getbyte(0) & 0x0f))
      else
        packet.setbyte(0, packet.getbyte(0) ^ (mask.getbyte(0) & 0x1f))
      end

      # Mask packet number
      packet_number_length.times do |i|
        offset = header_length + i
        packet.setbyte(offset, packet.getbyte(offset) ^ mask.getbyte(1 + i))
      end

      packet
    end

    private def level_to_pn_space(level)
      case level
      when Quic::Handshake::EncryptionLevel::INITIAL
        Quic::Protocol::PacketNumberSpace::INITIAL
      when Quic::Handshake::EncryptionLevel::HANDSHAKE
        Quic::Protocol::PacketNumberSpace::HANDSHAKE
      else
        Quic::Protocol::PacketNumberSpace::APPLICATION_DATA
      end
    end

    private def level_to_packet_type(level)
      case level
      when Quic::Handshake::EncryptionLevel::INITIAL then :initial
      when Quic::Handshake::EncryptionLevel::HANDSHAKE then :handshake
      when Quic::Handshake::EncryptionLevel::ZERO_RTT then :"0RTT"
      when Quic::Handshake::EncryptionLevel::ONE_RTT then :"1RTT"
      end
    end

    private def log_event(event)
      @qlog_writer&.log(event)
    end

    private def log_packet_sent(level:, packet_number:, frames:)
      return unless @qlog_writer

      log_event(Qlog::TransportEvents::PacketSent.new(
        packet_type: level_to_packet_type(level),
        packet_number: packet_number,
        frames: frames
      ))
    end

    private def log_packet_received(level:, packet_number:, frames:)
      return unless @qlog_writer

      log_event(Qlog::TransportEvents::PacketReceived.new(
        packet_type: level_to_packet_type(level),
        packet_number: packet_number,
        frames: frames
      ))
    end

    private def log_packet_dropped(level:, trigger:)
      return unless @qlog_writer

      log_event(Qlog::TransportEvents::PacketDropped.new(
        packet_type: level_to_packet_type(level),
        trigger: trigger
      ))
    end

    private def log_state_updated(old_state:, new_state:)
      return unless @qlog_writer

      log_event(Qlog::ConnectionEvents::ConnectionStateUpdated.new(
        old_state: old_state,
        new_state: new_state
      ))
    end
  end
end
