# frozen_string_literal: true

module Raiha::Next::QUIC
  class Streams
    # The receive side of flow control, of one stream or of the whole
    # connection: the limit told to the peer, how far the peer has sent,
    # how much has been consumed, and the window. Credit goes back as the
    # data is consumed, read by the application or abandoned, so that a
    # peer whose data is not read stops.
    #
    # A new limit, what is consumed plus the window, is due once what is
    # left of the old one is three quarters of the window or less; the
    # peer then still has three quarters of a window while the update
    # travels. Its value is made when the frame is put together, and the
    # window grows then too: when what was read since the last time it was
    # judged is over half the window and took less than four round trips'
    # share of it, the window doubles, up to its maximum. It stops about
    # four bandwidth-delay products wide, and never shrinks (RFC 9000
    # "Increasing Flow Control Limits").
    class ReceiveWindow
      # The share of the window left that makes a new limit due.
      UPDATE_THRESHOLD = Rational(3, 4)
      # Round trips to read a window in, faster than which it doubles.
      ROUND_TRIPS = 4

      attr_reader :size
      # The limit last told to the peer.
      attr_reader :limit
      # The end of the furthest data received.
      attr_reader :received
      attr_reader :consumed

      # `size` is the window, first told as the limit, and `max` the most it
      # grows to.
      def initialize(size:, max:, now:)
        @size = size
        @max = max
        @limit = size
        @received = 0
        @consumed = 0
        @blocked = false
        @resend = false
        start_period(now)
      end

      # The peer has sent up to `end_offset` in a frame of `frame_type`:
      # FLOW_CONTROL_ERROR past the limit.
      def receive(end_offset, frame_type:)
        if end_offset > @limit
          raise Violation.new("data up to #{end_offset} past the limit #{@limit}", code: ErrorCode::FLOW_CONTROL_ERROR, frame_type:)
        end
        @received = end_offset if end_offset > @received
      end

      # `bytes` more are read or abandoned.
      def consume(bytes)
        @consumed += bytes
      end

      # The peer is blocked by the limit: credit not yet told goes at once,
      # whatever the threshold. A peer blocked by a limit that has nothing
      # more to give is held back on purpose, and gets nothing.
      def blocked!
        @blocked = true
      end

      # A frame with limit `maximum` was lost: the limit goes again if it is
      # still the latest (loss recovery's design, "Retransmission").
      def lost(maximum)
        @resend = true if maximum == @limit
      end

      def update_due? = @resend || credit_due?

      # The limit to send now, made the one told: a new one when credit is
      # due, the window having first grown when it was read fast enough,
      # else the last one again. `rtt` is the smoothed RTT, nil before the
      # path's first sample, until which the window does not grow, as the
      # initial RTT is longer than most and would make it grow too soon.
      def advance(now:, rtt:)
        if credit_due?
          tune(now, rtt)
          @limit = next_limit
        end
        @blocked = false
        @resend = false
        @limit
      end

      # The window grows to `size` at least, as far as its maximum: the
      # connection's follows a stream's.
      def grow_to(size, now:)
        return if size <= @size
        @size = [size, @max].min
        start_period(now)
      end

      private def credit_due?
        return false if next_limit <= @limit
        @blocked || @limit - @consumed <= @size * UPDATE_THRESHOLD
      end

      # What is consumed plus the window, short of what a varint holds.
      private def next_limit = [@consumed + @size, Wire::Varint::MAX].min

      private def tune(now, rtt)
        read = @consumed - @period_consumed
        return if read <= @size / 2 || rtt.nil?
        @size = [2 * @size, @max].min if now - @period_start < ROUND_TRIPS * read.fdiv(@size) * rtt
        start_period(now)
      end

      private def start_period(now)
        @period_start = now
        @period_consumed = @consumed
      end
    end
  end
end
