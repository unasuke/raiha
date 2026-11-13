# frozen_string_literal: true

module Raiha::Next::QUIC::Test
  # A path model that drops each datagram with probability `rate` and lets
  # the rest through at once.
  class RandomLoss < Data.define(:rate)
    def initialize(rate:)
      raise ArgumentError, "rate is 0.0..1.0, not #{rate}" unless (0.0..1.0).cover?(rate)
      super
    end

    def start(random:) = State.new(rate, random)

    class State
      def initialize(rate, random)
        @rate = rate
        @random = random
        @queue = [] #: Array[Datagram]
      end

      def submit(datagram, now:)
        @queue << datagram unless @random.rand < @rate
      end

      def each_delivery(now:)
        queue = @queue
        @queue = []
        queue.each { |datagram| yield datagram }
      end

      def next_timeout = nil
    end
  end
end
