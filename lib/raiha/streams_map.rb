# frozen_string_literal: true

require_relative "stream"
require_relative "quic/protocol/stream_id"
require_relative "quic/protocol/perspective"
require_relative "quic/flow_control"

module Raiha
  class StreamsMap
    def initialize(perspective:, connection_flow_controller:, max_streams_bidi: 0, max_streams_uni: 0, stream_receive_window: 65536)
      @perspective = perspective
      @connection_flow_controller = connection_flow_controller
      @stream_receive_window = stream_receive_window

      @streams = {} #: Hash[Integer, Stream]
      @incoming_streams = Queue.new

      @stream_limit = Quic::FlowControl::StreamLimitController.new(
        max_bidi: max_streams_bidi,
        max_uni: max_streams_uni
      )

      @next_bidi_stream_id = @perspective == Quic::Protocol::Perspective::CLIENT ? 0 : 1
      @next_uni_stream_id = @perspective == Quic::Protocol::Perspective::CLIENT ? 2 : 3
    end

    def open_bidirectional_stream
      @stream_limit.open_bidi

      stream_id = Quic::Protocol::StreamID.new(@next_bidi_stream_id)
      @next_bidi_stream_id += 4

      create_stream(stream_id)
    end

    def open_unidirectional_stream
      @stream_limit.open_uni

      stream_id = Quic::Protocol::StreamID.new(@next_uni_stream_id)
      @next_uni_stream_id += 4

      create_stream(stream_id)
    end

    def accept_stream
      @incoming_streams.pop
    end

    def accept_stream_nonblock
      @incoming_streams.pop(true)
    rescue ThreadError
      nil
    end

    def get_or_create_stream(stream_id_value)
      stream_id = stream_id_value.is_a?(Quic::Protocol::StreamID) ? stream_id_value : Quic::Protocol::StreamID.new(stream_id_value)

      @streams[stream_id.value] ||= begin
        @stream_limit.accept_stream(stream_id)
        stream = create_stream(stream_id)
        @incoming_streams << stream
        stream
      end
    end

    def get_stream(stream_id)
      @streams[stream_id.is_a?(Integer) ? stream_id : stream_id.value]
    end

    def each_stream(&block)
      return enum_for(:each_stream) unless block_given?

      @streams.each_value(&block)
    end

    def active_streams_count
      @streams.size
    end

    def update_peer_max_streams_bidi(max)
      @stream_limit.update_peer_max_bidi(max)
    end

    def update_peer_max_streams_uni(max)
      @stream_limit.update_peer_max_uni(max)
    end

    private def create_stream(stream_id)
      flow_controller = Quic::FlowControl::StreamFlowController.new(
        stream_id: stream_id,
        receive_window: @stream_receive_window,
        send_window: 0,
        connection_flow_controller: @connection_flow_controller
      )

      stream = Stream.new(stream_id: stream_id, flow_controller: flow_controller)
      @streams[stream_id.value] = stream
      stream
    end
  end
end
