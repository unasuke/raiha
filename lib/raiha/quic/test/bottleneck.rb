# frozen_string_literal: true

module Raiha::Next::QUIC::Test
  # A path model of one bottleneck link: datagrams wait in a queue of
  # `queue` bytes, go out
  # one after another at `bandwidth` bits per second, and arrive `delay`
  # seconds after they have gone out. One that does not fit in the queue is
  # dropped (tail-drop). With a `ce_threshold`, an ECT(0) datagram that finds
  # more than that many bytes waiting ahead of it is marked CE, as DCTCP's
  # switches do; L4S's ECT(1) is not handled.
  class Bottleneck < Data.define(:bandwidth, :delay, :queue, :ce_threshold)
    def initialize(bandwidth:, delay:, queue:, ce_threshold: nil)
      raise ArgumentError, "bandwidth must be positive, not #{bandwidth}" unless bandwidth.positive?
      raise ArgumentError, "delay must not be negative, not #{delay}" if delay.negative?
      raise ArgumentError, "queue must be positive, not #{queue}" unless queue.positive?
      raise ArgumentError, "ce_threshold must not be negative, not #{ce_threshold}" if ce_threshold&.negative?
      super
    end

    def start(random:) = State.new(self)

    class State
      def initialize(model)
        @model = model
        # The datagrams not yet gone out: when each will have, and its size.
        @waiting = [] #: Array[[Float, Integer]]
        @busy_until = 0.0
        # The datagrams on the wire, in the order they arrive.
        @arrivals = [] #: Array[[Float, Datagram]]
      end

      def submit(datagram, now:)
        @waiting.shift while (first = @waiting.first) && first.first <= now
        size = datagram.payload.bytesize
        ahead = @waiting.sum(&:last)
        return if ahead + size > @model.queue
        threshold = @model.ce_threshold
        marked = threshold && ahead > threshold && datagram.ecn == :ect0
        gone = [now, @busy_until].max + size * 8.0 / @model.bandwidth
        @busy_until = gone
        @waiting << [gone, size]
        @arrivals << [gone + @model.delay, marked ? datagram.with(ecn: :ce) : datagram]
      end

      def each_delivery(now:)
        while (first = @arrivals.first) && first.first <= now
          @arrivals.shift
          yield first.last
        end
      end

      def next_timeout = @arrivals.first&.first
    end
  end
end
