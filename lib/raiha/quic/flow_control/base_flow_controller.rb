# frozen_string_literal: true

require_relative "../qerr"

module Raiha::Quic
  module FlowControl
    class BaseFlowController
      WINDOW_UPDATE_THRESHOLD = 0.25

      attr_reader :send_window
      attr_reader :receive_window
      attr_reader :bytes_sent
      attr_reader :bytes_read
      attr_reader :highest_received

      def initialize(receive_window:, send_window: 0)
        @receive_window = receive_window
        @send_window = send_window
        @bytes_sent = 0
        @bytes_read = 0
        @highest_received = 0
        @blocked = false
      end

      def send_window_size
        [@send_window - @bytes_sent, 0].max
      end

      def receive_window_size
        [@receive_window - @highest_received, 0].max
      end

      def add_bytes_sent(count)
        @bytes_sent += count

        if @bytes_sent > @send_window
          @blocked = true
          raise Qerr::FlowControlError.new("Send window exceeded")
        end
      end

      def update_highest_received(offset, length)
        end_offset = offset + length

        if end_offset > @receive_window
          raise Qerr::FlowControlError.new("Receive window exceeded")
        end

        @highest_received = [@highest_received, end_offset].max
      end

      def add_bytes_read(count)
        @bytes_read += count
      end

      def update_send_window(new_window)
        if new_window > @send_window
          @send_window = new_window
          @blocked = false
        end
      end

      # True when the peer is running low on send credit: our remaining
      # receive-side capacity (@receive_window - @highest_received) has
      # fallen below WINDOW_UPDATE_THRESHOLD of the initial window. In
      # that case the caller should queue a MAX_DATA / MAX_STREAM_DATA
      # frame carrying #get_window_update.
      def should_send_window_update?
        remaining_credit = @receive_window - @highest_received
        remaining_credit < (initial_receive_window * WINDOW_UPDATE_THRESHOLD)
      end

      def get_window_update
        @receive_window = @bytes_read + initial_receive_window
        @receive_window
      end

      def blocked?
        @blocked
      end

      def can_send?(count)
        send_window_size >= count
      end

      private def initial_receive_window
        raise NotImplementedError
      end
    end
  end
end
