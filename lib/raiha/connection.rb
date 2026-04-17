# frozen_string_literal: true

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
          handle_ack_frame(frame)
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
      frames = []
      frames << Quic::Wire::Frames::CryptoFrame.new.tap do |frame|
        frame.offset = 0
        frame.data = crypto_data
      end

      build_packet(frames, level: Quic::Handshake::EncryptionLevel::INITIAL)
    end

    # Get all packets ready to send
    def get_packets_to_send
      packets = []

      # Check for pending crypto data or ACK at each level
      [Quic::Handshake::EncryptionLevel::INITIAL,
       Quic::Handshake::EncryptionLevel::HANDSHAKE,
       Quic::Handshake::EncryptionLevel::ONE_RTT].each do |level|
        next unless @crypto_setup.available?(level)

        frames = []

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
        packets << packet if packet
      end

      # Check for pending stream data
      if @crypto_setup.available?(Quic::Handshake::EncryptionLevel::ONE_RTT)
        @pending_stream_frames&.each do |frame|
          packet = build_packet([frame], level: Quic::Handshake::EncryptionLevel::ONE_RTT)
          packets << packet if packet
        end
        @pending_stream_frames = []
      end

      packets
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

      @pending_stream_frames ||= []
      @pending_stream_frames << stream_frame
    end

    def complete_handshake
      old_state = @state
      @state = State::CONNECTED
      log_state_updated(old_state: old_state, new_state: @state)
      apply_peer_transport_parameters
    end

    private def apply_peer_transport_parameters
      peer_tp = @tls_adapter.peer_transport_parameters
      return unless peer_tp

      @streams.update_peer_max_streams_bidi(peer_tp.initial_max_streams_bidi) if peer_tp.initial_max_streams_bidi
      @streams.update_peer_max_streams_uni(peer_tp.initial_max_streams_uni) if peer_tp.initial_max_streams_uni
      @connection_flow_controller.update_send_window(peer_tp.initial_max_data) if peer_tp.initial_max_data
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
        rtt_stats: @rtt_stats
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

      @crypto_stream_buffers = {}

      @idle_timer = Quic::Timer.new
      reset_idle_timer
    end

    # Process a raw QUIC packet (with header protection and encryption)
    # A single UDP datagram may contain multiple coalesced QUIC packets (RFC 9000 Section 12.2)
    def handle_packet(data)
      return if @state == State::CLOSED

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

    private def handle_ack_frame(frame)
      @sent_packet_handler.received_ack(frame, pn_space: :application_data)
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
