# frozen_string_literal: true

module Raiha::QUIC::Test
  # A monotonic clock that moves only when told, in Float seconds like the
  # `now:` the core takes. No real time passes while a test runs on it.
  class VirtualClock
    attr_reader :now

    def initialize(now: 0.0)
      @now = now
    end

    # Moves the clock to `time`, which must not be in the past.
    def advance_to(time)
      raise ArgumentError, "the clock goes back from #{@now} to #{time}" if time < @now
      @now = time
    end

    def advance(seconds) = advance_to(@now + seconds)
  end
end
