# frozen_string_literal: true

module Raiha::Next::QUIC
  # The order the streams with something to send take turns in, a frame
  # a turn. Kept apart from Streams, which knows what each stream has to
  # send, so that the order can follow the priorities of RFC 9218.
  class Scheduler
    def initialize
      @turns = [] #: Array[Integer]
    end

    # `stream_id` has something to send: it takes turns from now on.
    def ready(stream_id)
      @turns << stream_id unless @turns.include?(stream_id)
    end

    # `stream_id` has nothing more to send, or is gone.
    def forget(stream_id)
      @turns.delete(stream_id)
    end

    # The stream whose turn it is; nil when none has a turn.
    def current = @turns.first

    # The stream whose turn it was took it: the next one's comes.
    def advance
      @turns.rotate!
    end
  end
end
