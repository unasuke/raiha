# frozen_string_literal: true

module Raiha::QUIC
  # The order the streams with something to send take turns in, a frame
  # a turn. Kept apart from Streams, which knows what each stream has to
  # send.
  #
  # The order follows the priorities of RFC 9218: an urgency from 0, the
  # most urgent, to 7, and whether the stream is incremental. A stream
  # takes turns only while no more urgent one has something to send. Of
  # those of one urgency, the incremental streams take turns together
  # with the one not incremental of the lowest ID, so that those not
  # incremental go one by one in the order of their IDs ("Server
  # Scheduling"), and neither kind starves the other, which the same
  # section leaves to the implementation. A stream nobody gave a priority
  # has DEFAULT_URGENCY and is incremental, so that streams take turns
  # alike unless told otherwise.
  class Scheduler
    URGENCIES = 0..7
    DEFAULT_URGENCY = 3
    # The place in a level's turns of the streams not incremental, which
    # the one of the lowest ID takes.
    SEQUENTIAL = -1

    # The streams of one urgency with something to send: the turns, and
    # those not incremental, by ID.
    class Level
      attr_reader :turns, :sequential

      def initialize
        @turns = [] #: Array[Integer]
        @sequential = [] #: Array[Integer]
      end

      def empty? = @turns.empty?

      def add(stream_id, incremental:)
        return @turns << stream_id if incremental
        @turns << SEQUENTIAL if @sequential.empty?
        index = @sequential.bsearch_index { |queued| queued > stream_id } || @sequential.size
        @sequential.insert(index, stream_id)
      end

      def remove(stream_id, incremental:)
        return @turns.delete(stream_id) if incremental
        @sequential.delete(stream_id)
        @turns.delete(SEQUENTIAL) if @sequential.empty?
      end

      def current
        turn = @turns.first
        turn == SEQUENTIAL ? @sequential.first : turn
      end
    end

    def initialize
      @levels = URGENCIES.map { Level.new }
      # The priorities given, as [urgency, incremental], and the streams
      # taking turns.
      @priorities = {} #: Hash[Integer, [Integer, bool]]
      @ready = {} #: Hash[Integer, true]
    end

    # `stream_id` goes with `urgency` and as `incremental` from now on,
    # behind those already taking turns at that urgency.
    def prioritize(stream_id, urgency:, incremental:)
      priority = [urgency, incremental] #: [Integer, bool]
      return if priority_of(stream_id) == priority
      ready = @ready.key?(stream_id)
      idle(stream_id)
      @priorities[stream_id] = priority
      ready(stream_id) if ready
    end

    # `stream_id` has something to send: it takes turns from now on.
    def ready(stream_id)
      return if @ready.key?(stream_id)
      @ready[stream_id] = true
      urgency, incremental = priority_of(stream_id)
      @levels.fetch(urgency).add(stream_id, incremental:)
    end

    # `stream_id` has nothing to send for now; its priority stays.
    def idle(stream_id)
      return unless @ready.delete(stream_id)
      urgency, incremental = priority_of(stream_id)
      @levels.fetch(urgency).remove(stream_id, incremental:)
    end

    # `stream_id` is gone.
    def forget(stream_id)
      idle(stream_id)
      @priorities.delete(stream_id)
    end

    # The stream whose turn it is, and its urgency; nil when none has a
    # turn.
    def current = level&.current

    def urgency = @levels.index { |level| !level.empty? }

    # The stream whose turn it was took it: the next one's comes.
    def advance
      level&.turns&.rotate!
    end

    # The most urgent level with streams taking turns.
    private def level = @levels.find { |level| !level.empty? }

    private def priority_of(stream_id) = @priorities.fetch(stream_id) { [DEFAULT_URGENCY, true] }
  end
end
