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
require_relative "qlog"

module Raiha
  class Connection
    module State
      HANDSHAKING = :handshaking
      CONNECTED = :connected
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

    def initialize(perspective:, src_connection_id:, dest_connection_id:, transport_parameters: nil, tls_config: nil, server_name: nil, alpn_protocols: nil)
      @perspective = perspective
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
          @streams.get_stream(frame.stream_id)&.update_send_window(frame.maximum_stream_data)
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

    def close(error_code: 0, reason: "")
      enter_draining_state
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
      should_pad = pad_to_min || (level == Quic::Handshake::EncryptionLevel::INITIAL && @perspective == :client)
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

    # Get all packets ready to send
    def get_packets_to_send
      packets = [] #: Array[String]

      # Check for pending crypto data or ACK at each level
      [Quic::Handshake::EncryptionLevel::INITIAL,
       Quic::Handshake::EncryptionLevel::HANDSHAKE,
       Quic::Handshake::EncryptionLevel::ONE_RTT].each do |level|
        next unless @crypto_setup.available?(level)

        frames = [] #: Array[Quic::Wire::Frame]

        ack_frame = pending_ack_frame(level)
        frames << ack_frame if ack_frame

        crypto_data = @crypto_setup.get_crypto_data(level: level)
        if crypto_data
          crypto_frame = Quic::Wire::Frames::CryptoFrame.new
          crypto_frame.offset = 0
          crypto_frame.data = crypto_data
          frames << crypto_frame
        end

        next if frames.empty?

        packet = build_packet(frames, level: level)
        emit_packet(packets, packet)
      end

      # Check for pending stream data
      if @crypto_setup.available?(Quic::Handshake::EncryptionLevel::ONE_RTT)
        @pending_stream_frames&.each do |frame|
          packet = build_packet([frame], level: Quic::Handshake::EncryptionLevel::ONE_RTT)
          emit_packet(packets, packet)
        end
        @pending_stream_frames = [] #: Array[Quic::Wire::Frames::StreamFrame]

        # Tell the peer about new flow-control credits when our receive
        # windows have advanced enough to need updating (RFC 9000 §4).
        emit_flow_control_updates(packets)

        # PATH_RESPONSE must echo back peer's PATH_CHALLENGE data (RFC 9000 §8.2.2).
        @pending_path_responses&.each do |response|
          packet = build_packet([response], level: Quic::Handshake::EncryptionLevel::ONE_RTT)
          emit_packet(packets, packet)
        end
        @pending_path_responses = [] #: Array[Quic::Wire::Frames::PathResponseFrame]

        # PATH_CHALLENGE initiated from this endpoint to probe the peer's path.
        @pending_path_challenges.each do |challenge|
          packet = build_packet([challenge], level: Quic::Handshake::EncryptionLevel::ONE_RTT)
          emit_packet(packets, packet)
        end
        @pending_path_challenges = [] #: Array[Quic::Wire::Frames::PathChallengeFrame]

        # RETIRE_CONNECTION_ID frames accumulated while processing peer's
        # NEW_CONNECTION_ID retire_prior_to directives (RFC 9000 §5.1.2).
        @pending_retire_connection_ids.each do |sequence_number|
          frame = Quic::Wire::Frames::RetireConnectionIdFrame.new
          frame.sequence_number = sequence_number
          packet = build_packet([frame], level: Quic::Handshake::EncryptionLevel::ONE_RTT)
          emit_packet(packets, packet)
        end
        @pending_retire_connection_ids = [] #: Array[Integer]

        # Stream aborts: RESET_STREAM (send-side) and STOP_SENDING
        # (receive-side) queued on individual streams (RFC 9000 §3.5).
        emit_stream_abort_frames(packets)

        # PTO probes (RFC 9002 §6.2.4): one ack-eliciting frame per firing.
        @pending_ping_frames&.each do |frame|
          packet = build_packet([frame], level: Quic::Handshake::EncryptionLevel::ONE_RTT)
          emit_packet(packets, packet)
        end
        @pending_ping_frames = [] #: Array[Quic::Wire::Frames::PingFrame]

        # Server → client handshake confirmation (RFC 9000 §19.20).
        if @pending_handshake_done
          frame = Quic::Wire::Frames::HandshakeDoneFrame.new
          packet = build_packet([frame], level: Quic::Handshake::EncryptionLevel::ONE_RTT)
          emit_packet(packets, packet)
          @pending_handshake_done = false
        end

        # Server → client address-validation tokens (RFC 9000 §19.7).
        @pending_new_tokens&.each do |token|
          frame = Quic::Wire::Frames::NewTokenFrame.new
          frame.token = token
          packet = build_packet([frame], level: Quic::Handshake::EncryptionLevel::ONE_RTT)
          emit_packet(packets, packet)
        end
        @pending_new_tokens = [] #: Array[String]
      end

      packets
    end

    private def emit_stream_abort_frames(packets)
      @streams.each_stream do |stream|
        reset_frame = stream.take_reset_stream_frame
        if reset_frame
          packet = build_packet([reset_frame], level: Quic::Handshake::EncryptionLevel::ONE_RTT)
          emit_packet(packets, packet)
        end

        stop_frame = stream.take_stop_sending_frame
        if stop_frame
          packet = build_packet([stop_frame], level: Quic::Handshake::EncryptionLevel::ONE_RTT)
          emit_packet(packets, packet)
        end
      end
    end

    # Peer-supplied alternate connection IDs we may route to (RFC 9000 §5.1).
    # Each entry is a hash with :sequence_number, :connection_id,
    # and :stateless_reset_token keys.
    def peer_connection_ids
      @peer_connection_ids.dup
    end

    # Emit MAX_DATA / MAX_STREAM_DATA frames whenever the connection-level or
    # any stream's receive window has fallen below the update threshold
    # (BaseFlowController#should_send_window_update?). Each update frame
    # goes out in its own 1-RTT packet.
    private def emit_flow_control_updates(packets)
      if @connection_flow_controller.should_send_window_update?
        new_limit = @connection_flow_controller.get_window_update
        frame = Quic::Wire::Frames::MaxDataFrame.new
        frame.maximum_data = new_limit
        packet = build_packet([frame], level: Quic::Handshake::EncryptionLevel::ONE_RTT)
        emit_packet(packets, packet)
      end

      @streams.each_stream do |stream|
        fc = stream.flow_controller
        next unless fc.should_send_window_update?

        new_limit = fc.get_window_update
        frame = Quic::Wire::Frames::MaxStreamDataFrame.new
        frame.stream_id = stream.stream_id.value
        frame.maximum_stream_data = new_limit
        packet = build_packet([frame], level: Quic::Handshake::EncryptionLevel::ONE_RTT)
        emit_packet(packets, packet)
      end
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

    # Accepts a built packet into the outgoing list if the server's
    # anti-amplification budget permits (RFC 9000 §8.1): prior to address
    # validation, cumulative bytes sent MUST NOT exceed 3x bytes received.
    # Dropped packets are discarded here; they'll be rebuilt on the next
    # get_packets_to_send after more peer data grows the budget, or after
    # the handshake completes and the limit is lifted.
    private def emit_packet(packets, packet)
      return unless packet

      if @perspective == Quic::Protocol::Perspective::SERVER && !@address_validated
        budget = 3 * @bytes_received_from_peer - @bytes_sent_to_peer
        return if packet.bytesize > budget
      end

      packets << packet
      @bytes_sent_to_peer += packet.bytesize
    end

    # Queue a PATH_RESPONSE carrying the 8-byte challenge received from the peer.
    private def queue_path_response(challenge_data)
      response = Quic::Wire::Frames::PathResponseFrame.new
      response.data = challenge_data

      @pending_path_responses ||= [] #: Array[Quic::Wire::Frames::PathResponseFrame]
      @pending_path_responses << response
    end

    # Match a received PATH_RESPONSE against our outstanding challenges.
    # RFC 9000 §8.2.3: a response with non-matching data is a PROTOCOL_VIOLATION.
    # The RFC-correct reaction is a connection close; for now we just ignore
    # mismatches. A matching response validates the current path.
    private def handle_path_response(response_data)
      return unless @outstanding_path_challenges.delete(response_data)

      @peer_path_validated = true
    end

    # Track a new alternate connection ID issued by the peer. When
    # retire_prior_to is non-zero, every known entry with a smaller sequence
    # number MUST be retired (RFC 9000 §5.1.2) by sending
    # RETIRE_CONNECTION_ID back.
    private def handle_new_connection_id(frame)
      # Duplicate sequence_number is a PROTOCOL_VIOLATION per §19.15; for
      # now just ignore re-issues of the same sequence number.
      return if @peer_connection_ids.any? { |entry| entry[:sequence_number] == frame.sequence_number }

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
      stream_frame = Quic::Wire::Frames::StreamFrame.new
      stream_frame.stream_id = stream_id.is_a?(Integer) ? stream_id : stream_id.value
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

      # Draining state is governed by drain_timer, not idle_timer.
      return if @state == State::DRAINING

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
      raise Raiha::Error, "NEW_TOKEN may only be sent by the server" unless @perspective == Quic::Protocol::Perspective::SERVER

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
    private def on_packet_lost(packet, _pn_space)
      packet.frames.each { |frame| requeue_lost_frame(frame) }
    end

    # RFC 9002 §6.2.4: on PTO expiry, emit one ack-eliciting probe packet to
    # provoke a fresh ACK from the peer. A PING frame is always sufficient
    # and doesn't conflict with pending application data.
    private def on_pto_fired
      @pending_ping_frames ||= [] #: Array[Quic::Wire::Frames::PingFrame]
      @pending_ping_frames << Quic::Wire::Frames::PingFrame.new
    end

    private def requeue_lost_frame(frame)
      case frame
      when Quic::Wire::Frames::StreamFrame
        @pending_stream_frames ||= [] #: Array[Quic::Wire::Frames::StreamFrame]
        @pending_stream_frames << frame
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
      # ACK / PADDING / PATH_CHALLENGE / PATH_RESPONSE / CRYPTO / PING /
      # MAX_* / CONNECTION_CLOSE aren't retransmitted here: ACK and
      # PADDING are never retransmitted; PATH_RESPONSE and CRYPTO have
      # specialised recovery paths (PATH_CHALLENGE re-initiation, CRYPTO
      # offset tracking) that are not implemented yet; MAX_* frames are
      # self-healing because they always carry the latest limit and
      # re-emit on the next window-update check; PING is produced fresh
      # by PTO firings, so a lost PING would be replaced by the next PTO.
      end
    end

    private def handle_new_token_frame(frame)
      # RFC 9000 §19.7: a client MUST treat a NEW_TOKEN received from a
      # server as invalid if... it's actually only invalid in the other
      # direction (peer → client is legal). Servers MUST treat receipt of
      # NEW_TOKEN as a PROTOCOL_VIOLATION; we silently drop it for now
      # until the transport-error emission path exists.
      return unless @perspective == Quic::Protocol::Perspective::CLIENT

      @peer_issued_token = frame.token
    end

    private def handle_reset_stream_frame(frame)
      stream = @streams.get_or_create_stream(frame.stream_id)
      stream.handle_reset_stream(
        error_code: frame.application_protocol_error_code,
        final_size: frame.final_size
      )
    end

    private def handle_stop_sending_frame(frame)
      stream = @streams.get_stream(frame.stream_id)
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
      queue_handshake_done if @perspective == Quic::Protocol::Perspective::SERVER
    end

    private def queue_handshake_done
      @pending_handshake_done = true
    end

    private def apply_peer_transport_parameters
      peer_tp = @tls_adapter.peer_transport_parameters
      return unless peer_tp

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

      @idle_timer = Quic::Timer.new
      reset_idle_timer
    end

    # Process a raw QUIC packet (with header protection and encryption)
    # A single UDP datagram may contain multiple coalesced QUIC packets (RFC 9000 Section 12.2)
    def handle_packet(data)
      return if @state == State::CLOSED

      # RFC 9000 §10.3.1: check the final 16 bytes of the datagram against
      # any stateless reset tokens the peer has advertised. A match means
      # the peer has lost connection state and is asking us to abandon it
      # immediately — enter draining and stop processing.
      if Quic::StatelessReset.match_token?(data, known_peer_reset_tokens)
        enter_draining_state
        return
      end

      @bytes_received_from_peer += data.bytesize

      offset = 0
      while offset < data.bytesize
        remaining = data[offset..]
        first_byte = remaining.getbyte(0)

        # RFC 9000 Section 17.2/17.3: the Fixed Bit (bit 6) MUST be 1 for both Long
        # and Short Header packets. A first byte below 0x40 is datagram-level padding
        # (some implementations pad coalesced datagrams with zero bytes to 1200).
        break if first_byte < 0x40

        if (first_byte & 0x80) != 0
          consumed = handle_long_header_packet(remaining, Quic::Wire::Buffer.new(remaining))
          break unless consumed && consumed > 0
          offset += consumed
        else
          handle_short_header_packet(remaining, Quic::Wire::Buffer.new(remaining))
          break # Short header packets are always last in a coalesced datagram
        end
      end
    rescue => error
      # Log error but don't crash the connection
      $stderr.puts "Connection error handling packet: #{error.class}: #{error.message}" if $DEBUG
    end

    # Returns the number of bytes consumed, or nil on failure
    private def handle_long_header_packet(data, buffer)
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
          ack_eliciting: frames.any?(&:ack_eliciting?)
        )
        handle_frames(frames, level: level)
      rescue OpenSSL::Cipher::CipherError
        log_packet_dropped(level: level, trigger: :decryption_failure)
      end

      total_packet_size
    end

    private def handle_short_header_packet(data, buffer)
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
          ack_eliciting: frames.any?(&:ack_eliciting?)
        )
        handle_frames(frames, level: level)
      rescue OpenSSL::Cipher::CipherError
        log_packet_dropped(level: level, trigger: :decryption_failure)
      end
    end

    # Update connection IDs when receiving the first Initial packet from the peer.
    private def update_connection_ids_from_initial(header)
      if @perspective == :client && header.source_connection_id
        # RFC 9000 Section 7.2: client updates DCID to server's SCID
        @dest_connection_id = header.source_connection_id
      elsif @perspective == :server && !@initial_keys_rederived
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
      stream = @streams.get_or_create_stream(frame.stream_id)
      stream.receive_data(frame.offset, frame.data, fin: frame.fin)
    end

    private def enter_draining_state
      old_state = @state
      @state = State::DRAINING
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
