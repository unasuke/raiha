# frozen_string_literal: true

require_relative "base_flow_controller"

module Raiha::Quic
  module FlowControl
    class ConnectionFlowController < BaseFlowController
      def initialize(receive_window:, send_window:)
        super(receive_window: receive_window, send_window: send_window)
        @initial_receive_window = receive_window
      end

      def update_highest_received(length)
        @highest_received += length

        if @highest_received > @receive_window
          raise Qerr::FlowControlError.new("Connection receive window exceeded")
        end
      end

      private def initial_receive_window
        @initial_receive_window
      end
    end
  end
end
