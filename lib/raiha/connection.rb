# frozen_string_literal: true

require_relative "stream"
require_relative "streams_map"
require_relative "quic/protocol"
require_relative "quic/wire/frame_parser"
require_relative "quic/wire/long_header"
require_relative "quic/wire/short_header"
require_relative "quic/handshake/encryption_level"
require_relative "quic/handshake/initial_aead"
require_relative "quic/handshake/transport_parameters"
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

      @idle_timer = Quic::Timer.new
      reset_idle_timer
    end

    private def handle_ack_frame(frame)
      @sent_packet_handler.received_ack(frame, pn_space: :application_data)
    end

    private def handle_crypto_frame(frame)
      # Crypto data is handled by CryptoSetup (to be integrated)
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
  end
end
