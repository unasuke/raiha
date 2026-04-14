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
      end

      def can_open_bidi?
        @opened_bidi < @peer_max_bidi
      end

      def can_open_uni?
        @opened_uni < @peer_max_uni
      end

      def open_bidi
        raise Qerr::StreamLimitError.new("Bidirectional stream limit exceeded") unless can_open_bidi?

        @opened_bidi += 1
      end

      def open_uni
        raise Qerr::StreamLimitError.new("Unidirectional stream limit exceeded") unless can_open_uni?

        @opened_uni += 1
      end

      def update_peer_max_bidi(max)
        @peer_max_bidi = [max, @peer_max_bidi].max
      end

      def update_peer_max_uni(max)
        @peer_max_uni = [max, @peer_max_uni].max
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
