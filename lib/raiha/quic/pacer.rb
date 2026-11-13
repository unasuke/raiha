# frozen_string_literal: true

module Raiha::QUIC
  # The pacer of a path (RFC 9002 "Pacing"): a token bucket that fills at
  # the congestion controller's pacing rate, up to `capacity`, the most RFC
  # 9002 lets go in a burst, or up to what the rate gives in `granularity`
  # seconds when that is more, as quicly's burst window is, so that waking
  # no more often than that does not slow the rate down. A datagram goes
  # while the bucket holds its worth, and takes what it sends from it; an
  # idle path saves up no more than one burst. When a datagram has to wait,
  # `release_at` is when it may go, rounded up to `granularity`, so that the
  # loop that sends wakes no more often than that. No rate, before an RTT
  # sample or on a path of no delay, is no pacing.
  class Pacer
    def initialize(capacity:, granularity:)
      @capacity = capacity
      @granularity = granularity
      @tokens = capacity.to_f
      @filled_at = nil #: Float?
    end

    # Whether a datagram of `size` bytes may go at `now`, at `rate` bytes a
    # second.
    def ready?(size, rate, now)
      fill(rate, now)
      @tokens >= size
    end

    # The burst the bucket holds from now on, as the datagrams of the path
    # grow; what it holds now stays.
    attr_writer :capacity

    # A datagram of `bytes` went; one that went without waiting, a probe
    # say, still takes its bytes, and the next waits the longer.
    def sent(bytes) = @tokens -= bytes

    # When a datagram of `size` bytes may go, at `rate`: nil when it may go
    # at once.
    def release_at(size, rate, now)
      return nil if ready?(size, rate, now) || rate.nil?
      wait = (size - @tokens) / rate
      now + (wait / @granularity).ceil * @granularity
    end

    private def fill(rate, now)
      filled_at = @filled_at
      @filled_at = now
      return @tokens = @capacity.to_f if rate.nil?
      @tokens = [@tokens + rate * (now - filled_at), [@capacity.to_f, rate * @granularity].max].min if filled_at && now > filled_at
    end
  end
end
