# frozen_string_literal: true

require_relative "base_flow_controller"

module Raiha::Quic
  module FlowControl
    class StreamFlowController < BaseFlowController
      attr_reader :stream_id
      attr_reader :connection_flow_controller

      def initialize(stream_id:, receive_window:, send_window:, connection_flow_controller:)
        super(receive_window: receive_window, send_window: send_window)
        @stream_id = stream_id
        @connection_flow_controller = connection_flow_controller
        @initial_receive_window = receive_window
        @final_size = nil
      end

      def send_window_size
        stream_window = super
        connection_window = @connection_flow_controller.send_window_size
        [stream_window, connection_window].min
      end

      def add_bytes_sent(count)
        super(count)
        @connection_flow_controller.add_bytes_sent(count)
      end

      def update_highest_received(offset, length)
        super(offset, length)
        @connection_flow_controller.update_highest_received(length)
      end

      def add_bytes_read(count)
        super(count)
        @connection_flow_controller.add_bytes_read(count)
      end

      def set_final_size(size)
        if @final_size && @final_size != size
          raise Qerr::FinalSizeError.new("Final size changed")
        end

        if size < @highest_received
          raise Qerr::FinalSizeError.new("Final size less than highest received")
        end

        @final_size = size
      end

      def has_final_size?
        !@final_size.nil?
      end

      def fully_received?
        @final_size && @highest_received >= @final_size
      end

      private def initial_receive_window
        @initial_receive_window
      end
    end
  end
end
