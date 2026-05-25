# frozen_string_literal: true

require_relative "../qerr"

module Raiha::Quic
  module FlowControl
    class StreamLimitController
      def initialize(max_bidi:, max_uni:)
        @max_bidi = max_bidi
        @max_uni = max_uni
        @opened_bidi = 0
        @opened_uni = 0
        @peer_max_bidi = 0
        @peer_max_uni = 0
        # Pending STREAMS_BLOCKED signal (RFC 9000 §19.14): set when we
        # tried to open a new stream but the peer's max_streams stopped
        # us. Cleared when the peer raises the limit.
        @pending_blocked_bidi = nil #: Integer?
        @pending_blocked_uni = nil #: Integer?
      end

      def can_open_bidi?
        @opened_bidi < @peer_max_bidi
      end

      def can_open_uni?
        @opened_uni < @peer_max_uni
      end

      def open_bidi
        unless can_open_bidi?
          @pending_blocked_bidi = @peer_max_bidi
          raise Qerr::StreamLimitError.new("Bidirectional stream limit exceeded")
        end

        @opened_bidi += 1
      end

      def open_uni
        unless can_open_uni?
          @pending_blocked_uni = @peer_max_uni
          raise Qerr::StreamLimitError.new("Unidirectional stream limit exceeded")
        end

        @opened_uni += 1
      end

      def update_peer_max_bidi(max)
        if max > @peer_max_bidi
          @peer_max_bidi = max
          @pending_blocked_bidi = nil
        end
      end

      def update_peer_max_uni(max)
        if max > @peer_max_uni
          @peer_max_uni = max
          @pending_blocked_uni = nil
        end
      end

      def pending_bidi_blocked_signal?
        !@pending_blocked_bidi.nil?
      end

      def pending_uni_blocked_signal?
        !@pending_blocked_uni.nil?
      end

      def take_bidi_blocked_signal
        limit = @pending_blocked_bidi || raise("take_bidi_blocked_signal called without a pending signal")
        @pending_blocked_bidi = nil
        limit
      end

      def take_uni_blocked_signal
        limit = @pending_blocked_uni || raise("take_uni_blocked_signal called without a pending signal")
        @pending_blocked_uni = nil
        limit
      end

      def accept_stream(stream_id)
        if stream_id.bidirectional?
          if stream_id.to_i / 4 >= @max_bidi
            raise Qerr::StreamLimitError.new("Peer exceeded bidirectional stream limit")
          end
        else
          if (stream_id.to_i - 2) / 4 >= @max_uni
            raise Qerr::StreamLimitError.new("Peer exceeded unidirectional stream limit")
          end
        end
      end
    end
  end
end
