# frozen_string_literal: true

module Raiha::QUIC
  class Recovery
    # The bandwidth estimator of a path, of the form of quicly's ratemeter:
    # the bytes acknowledged while the sender was held back by the
    # congestion window or pacing with data waiting, in samples of 50 ms at
    # least, the latest ten kept. Held back, the packets sent from then on
    # count: an ACK whose largest newly acknowledged packet is one of them
    # adds to the sample being taken, and one past them, once sending is no
    # longer held back, ends it. What goes while the application has nothing
    # to send says nothing of the path and counts for nothing. The rate goes
    # out in qlog only; no congestion controller uses it.
    class RateMeter
      # Seconds.
      PERIOD = 0.05
      SAMPLES = 10

      def initialize
        # The samples taken, oldest first: their seconds and bytes.
        @samples = [] #: Array[[Float, Integer]]
        # The packet numbers sent while held back: from, and until once no
        # longer.
        @limited_from = nil #: Integer?
        @limited_until = nil #: Integer?
        @acked = 0
        # The sample being taken: when it started and the bytes acknowledged
        # then, nil while none is, and what it holds so far.
        @started_at = nil #: Float?
        @started_acked = 0
        @elapsed = 0.0
        @bytes = 0
      end

      # Sending stopped, held back by the window or pacing with data waiting
      # (`limited`) or not; the next packet will be numbered
      # `next_packet_number` at least.
      def sending_stopped(limited:, next_packet_number:)
        return if limited == limited?
        return @limited_until = next_packet_number unless limited
        # A sample of the last time held back, still waiting for an ACK past
        # it, ends here, and one with nothing in it yet is dropped.
        @elapsed.positive? ? commit : @started_at = nil
        @limited_from = next_packet_number
        @limited_until = nil
      end

      # `bytes` in flight were acknowledged at `now`, the largest packet newly
      # acknowledged numbered `largest`.
      def on_ack(bytes, largest:, now:)
        @acked += bytes
        from = @limited_from or return
        till = @limited_until
        if largest >= from && (till.nil? || largest < till)
          take(now)
        elsif till && largest >= till && @started_at
          @elapsed.positive? ? commit : @started_at = nil
          @limited_from = @limited_until = nil
        end
      end

      # Bytes a second over the samples and the one being taken, nil before
      # any.
      def rate
        elapsed = @samples.sum(@elapsed) { |seconds, _bytes| seconds }
        bytes = @samples.sum(@bytes) { |_seconds, bytes| bytes }
        bytes / elapsed if elapsed.positive?
      end

      private def limited? = !@limited_from.nil? && @limited_until.nil?

      private def take(now)
        started_at = @started_at or return start(now)
        @elapsed = now - started_at
        @bytes = @acked - @started_acked
        return if @elapsed < PERIOD
        commit
        start(now)
      end

      private def start(now)
        @started_at = now
        @started_acked = @acked
      end

      private def commit
        @samples << [@elapsed, @bytes]
        @samples.shift if @samples.size > SAMPLES
        @started_at = nil
        @elapsed = 0.0
        @bytes = 0
      end
    end
  end
end
