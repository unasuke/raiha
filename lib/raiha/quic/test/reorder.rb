# frozen_string_literal: true

module Raiha::QUIC::Test
  # A path model that holds back a datagram with probability `rate` until
  # the next one has gone past it, so that the two arrive the other way
  # round. One with nothing behind it goes after `hold` seconds. The rest go
  # through at once.
  class Reorder < Data.define(:rate, :hold)
    def initialize(rate:, hold: 0.01)
      raise ArgumentError, "rate is 0.0..1.0, not #{rate}" unless (0.0..1.0).cover?(rate)
      raise ArgumentError, "hold must be positive, not #{hold}" unless hold.positive?
      super
    end

    def start(random:) = State.new(rate, hold, random)

    class State
      def initialize(rate, hold, random)
        @rate = rate
        @hold = hold
        @random = random
        @queue = [] #: Array[Datagram]
        # The datagram held back and when it goes regardless.
        @held = nil #: [Datagram, Float]?
      end

      def submit(datagram, now:)
        if (held = @held)
          @queue << datagram << held.first
          @held = nil
        elsif @random.rand < @rate
          @held = [datagram, now + @hold]
        else
          @queue << datagram
        end
      end

      def each_delivery(now:)
        if (held = @held) && held.last <= now
          @queue << held.first
          @held = nil
        end
        queue = @queue
        @queue = []
        queue.each { |datagram| yield datagram }
      end

      def next_timeout = @held&.last
    end
  end
end
