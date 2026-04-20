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
        # Pending (DATA|STREAM_DATA)_BLOCKED signal: set to the send_window
        # value at which we first noticed we wanted to send but couldn't
        # (RFC 9000 §19.12 / §19.13). Cleared by update_send_window and
        # by the connection's emit path.
        @pending_blocked_limit = nil #: Integer?
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
          @pending_blocked_limit = nil
        end
      end

      # We tried to send but were capped by flow control. The latest
      # send_window value is remembered so the connection can emit a
      # (DATA|STREAM_DATA)_BLOCKED frame naming the same limit (RFC 9000
      # §19.12 / §19.13). Signalling the same limit twice is wasteful
      # and not required, so subsequent calls at the same limit are no-ops.
      def mark_blocked_at(limit)
        @pending_blocked_limit = limit
      end

      def at_send_limit?
        @bytes_sent >= @send_window
      end

      def pending_blocked_signal?
        !@pending_blocked_limit.nil?
      end

      # Returns the limit at which we were blocked and clears the pending
      # flag. The connection calls this when it emits the frame.
      def take_blocked_signal
        limit = @pending_blocked_limit
        @pending_blocked_limit = nil
        limit
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
