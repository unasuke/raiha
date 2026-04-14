# frozen_string_literal: true

require_relative "stream"
require_relative "streams_map"
require_relative "quic/protocol"
require_relative "quic/wire/frame_parser"
require_relative "quic/wire/long_header"
require_relative "quic/wire/short_header"
require_relative "quic/handshake/encryption_level"
require_relative "quic/handshake/crypto_setup"
require_relative "quic/handshake/transport_parameters"
require_relative "quic/wire/buffer"
require_relative "quic/ack_handler"
require_relative "quic/congestion"
require_relative "quic/flow_control"
require_relative "quic/timer"

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

    def initialize(perspective:, src_connection_id:, dest_connection_id:, transport_parameters: nil)
      @perspective = perspective
      @src_connection_id = src_connection_id
      @dest_connection_id = dest_connection_id
      @state = State::HANDSHAKING
      @transport_parameters = transport_parameters || Quic::Handshake::TransportParameters.new

      setup_components
    end

    def handle_frames(frames)
      frames.each do |frame|
        case frame
        when Quic::Wire::Frames::AckFrame
          handle_ack_frame(frame)
        when Quic::Wire::Frames::CryptoFrame
          handle_crypto_frame(frame)
        when Quic::Wire::Frames::StreamFrame
          handle_stream_frame(frame)
        when Quic::Wire::Frames::MaxDataFrame
          @connection_flow_controller.update_send_window(frame.maximum_data)
        when Quic::Wire::Frames::MaxStreamDataFrame
          stream = @streams.get_stream(frame.stream_id)
          stream&.flow_controller&.update_send_window(frame.maximum_stream_data)
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

    def close(error_code: 0, reason: "")
      enter_draining_state
    end

    # Build a QUIC packet containing the given frames at the specified encryption level
    def build_packet(frames, level:)
      return nil if frames.empty?

      packet_number = @sent_packet_handler.get_next_packet_number(level_to_pn_space(level))

      # Serialize frames
      frame_buf = Quic::Wire::Buffer.new
      frames.each { |frame| frame_buf.write(frame.serialize) }
      payload = frame_buf.to_s

      # Encode packet number
      encoded_packet_number = encode_packet_number(packet_number.value)

      # Build header
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

      # Check for pending crypto data at each level
      [Quic::Handshake::EncryptionLevel::INITIAL,
       Quic::Handshake::EncryptionLevel::HANDSHAKE,
       Quic::Handshake::EncryptionLevel::ONE_RTT].each do |level|
        next unless @crypto_setup.available?(level)

        crypto_data = @crypto_setup.get_crypto_data(level: level)
        if crypto_data
          crypto_frame = Quic::Wire::Frames::CryptoFrame.new
          crypto_frame.offset = 0
          crypto_frame.data = crypto_data
          packet = build_packet([crypto_frame], level: level)
          packets << packet if packet
        end
      end

      packets
    end

    def complete_handshake
      @state = State::CONNECTED
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

      @idle_timer = Quic::Timer.new
      reset_idle_timer
    end

    # Process a raw QUIC packet (with header protection and encryption)
    def handle_packet(data)
      return if @state == State::CLOSED

      buffer = Quic::Wire::Buffer.new(data)
      first_byte = buffer.read_uint8
      buffer.seek(0)

      if (first_byte & 0x80) != 0
        handle_long_header_packet(data, buffer)
      else
        handle_short_header_packet(data, buffer)
      end
    rescue => error
      # Log error but don't crash the connection
      $stderr.puts "Connection error handling packet: #{error.class}: #{error.message}" if $DEBUG
    end

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
        return
      end

      return unless @crypto_setup.available?(level)

      # Read packet number (after header, before payload)
      packet_number_offset = buffer.pos
      packet_number_bytes = buffer.read(header.packet_number_length)
      packet_number = decode_packet_number(packet_number_bytes)

      # Decrypt payload
      payload_data = buffer.read(header.payload_length - header.packet_number_length)
      aad = data[0...packet_number_offset] + packet_number_bytes

      begin
        decrypted = @crypto_setup.decrypt(payload_data, packet_number: packet_number, aad: aad, level: level)
        frames = Quic::Wire::FrameParser.parse(Quic::Wire::Buffer.new(decrypted))
        handle_frames(frames)
      rescue OpenSSL::Cipher::CipherError
        # Decryption failed, drop packet
      end
    end

    private def handle_short_header_packet(data, buffer)
      # Short header processing requires knowing connection ID length
      # For now, just parse what we can
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

    private def handle_crypto_frame(frame)
      @crypto_setup.queue_crypto_data(frame.data, level: Quic::Handshake::EncryptionLevel::INITIAL)
    end

    private def handle_stream_frame(frame)
      stream = @streams.get_or_create_stream(frame.stream_id)
      stream.receive_data(frame.offset, frame.data, fin: frame.fin)
    end

    private def enter_draining_state
      @state = State::DRAINING

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
      sample_offset = header_length + packet_number_length + 4
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
  end
end
