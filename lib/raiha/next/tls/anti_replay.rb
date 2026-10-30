# frozen_string_literal: true

module Raiha::Next::TLS
  # Records the ClientHellos whose 0-RTT a server took, so that it takes the
  # 0-RTT of each at most once (RFC 9846 "0-RTT and Anti-Replay", "Client
  # Hello Recording"). A record answers
  #
  #   check(binder, expires_at:, now:) -> :accepted | :replayed | :unavailable
  #
  # for the binder of a ClientHello that verified and passed the freshness
  # check: :accepted when it was not recorded and now is, :replayed when it
  # was or may have been, :unavailable when the record cannot tell. It keeps
  # what it recorded until `expires_at` at least. It must not raise; what it
  # cannot tell is :unavailable, and a server takes no 0-RTT but on
  # :accepted.
  module AntiReplay
    # The longest a record must be kept, in seconds: the window of the
    # freshness check, 10 seconds early and 1 late.
    WINDOW = 11

    # Records kept in memory, by one instance (a Ractor or a process): each
    # ClientHello's 0-RTT is taken at most once by it, but once by each
    # instance that can open the ticket.
    #
    # Two generations of WINDOW seconds by the `now:` it is given, so that a
    # record stays from 11 to 22 seconds. For WINDOW seconds after it is
    # made it records but answers :unavailable, so that a ClientHello whose
    # 0-RTT was taken before a restart is not taken again (RFC 9846 "Client
    # Hello Recording"). `warmup: false` skips that, and is right only when
    # every ticket key it opens tickets with is newer than the record, such
    # as keys made at random on start: then no ClientHello from before
    # opens. With keys that outlive it, a replay of 0-RTT taken before a
    # restart could be taken again.
    class Memory
      def initialize(now:, warmup: true)
        raise ArgumentError, "now must be a Time" unless now.is_a?(Time)
        raise ArgumentError, "warmup must be true or false" unless warmup == true || warmup == false
        @current = {} #: Hash[String, true]
        @previous = {} #: Hash[String, true]
        @rotated_at = now.to_r
        @available_at = warmup ? now.to_r + WINDOW : now.to_r
        @lock = Thread::Mutex.new
      end

      def check(binder, expires_at:, now:)
        @lock.synchronize do
          rotate(now.to_r)
          return :replayed if @current.key?(binder) || @previous.key?(binder)
          # Not kept that long: the record could not tell a replay then.
          return :unavailable if expires_at.to_r > now.to_r + WINDOW
          @current[binder] = true
          now.to_r < @available_at ? :unavailable : :accepted
        end
      end

      def inspect = "#<#{self.class.name}>"

      # A generation is dropped WINDOW seconds after the one after it began,
      # so a record outlives WINDOW seconds; a clock that went back drops
      # nothing.
      private def rotate(now)
        elapsed = now - @rotated_at
        return if elapsed < WINDOW
        @previous = elapsed < 2 * WINDOW ? @current : {}
        @current = {}
        @rotated_at = now
      end
    end
  end
end
