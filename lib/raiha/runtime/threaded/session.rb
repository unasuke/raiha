# frozen_string_literal: true

module Raiha::Runtime
  module Threaded
    # The threads a client or a server of the runtime starts to run the
    # application, each named, and how many of them may run at once: a
    # thread takes a place before it starts, waiting while `max` are
    # taken, and gives it back once it ends. A server has one of these for
    # the threads of streams and requests, and one for those of its
    # connections' handlers, whose places it only counts. The threads
    # started are kept until they end, however long their connections
    # last, so that they can be joined.
    #
    # Its lock is its own, apart from a driver's core lock, and nothing
    # waits for a place holding the core lock; what wakes those waiting
    # (`wake`) may hold it.
    class Threads
      attr_reader :max

      def initialize(max)
        raise ArgumentError, "max_threads is an Integer of 1 or more, not #{max.inspect}" unless max.is_a?(Integer) && max.positive?
        @max = max
        @lock = Thread::Mutex.new
        @freed = Thread::ConditionVariable.new
        @taken = 0
        @running = {} #: Hash[Thread, true]
        @running.compare_by_identity
      end

      # How many places are taken.
      def taken = @lock.synchronize { @taken }

      # Takes a place, waiting while there is none, until the block is true:
      # whether one was taken.
      def take
        @lock.synchronize do
          until @taken < @max
            return false if yield
            @freed.wait(@lock)
          end
          return false if yield
          @taken += 1
          true
        end
      end

      # Takes a place without waiting, counting a thread that runs whether
      # or not there is room: for a connection's handler, which the server
      # counts before it takes the connection.
      def count
        @lock.synchronize { @taken += 1 }
        nil
      end

      def give_back
        @lock.synchronize do
          @taken -= 1
          @freed.signal
        end
      end

      # Wakes what waits for a place, to look again at what it waits until.
      def wake
        @lock.synchronize { @freed.broadcast }
      end

      # Starts a thread named `name` for the block, on a place taken; the
      # place is given back once it ends, or at once when the thread cannot
      # be started, which raises.
      def start(name)
        @lock.synchronize do
          thread = Thread.new do
            # Until it is kept among those running.
            @lock.synchronize { nil }
            yield
          ensure
            @lock.synchronize do
              @running.delete(Thread.current)
              @taken -= 1
              @freed.signal
            end
          end
          thread.name = name
          @running[thread] = true
          thread
        end
      rescue ThreadError
        give_back
        raise
      end

      # The threads started and not yet ended.
      def running = @lock.synchronize { @running.keys }

      # Waits for the threads started to end, until `deadline` at most;
      # those running on are left to.
      def join(deadline)
        running.each do |thread|
          left = deadline - Driver.clock
          break unless left.positive?
          thread.join(left)
        end
        nil
      end
    end

    # A QUIC connection the threads of the application use as if it
    # blocked, as the Session of fibers is: a read waits for data, a write
    # for room, an open for a stream the peer allows, each on a condition
    # of its Driver's core lock, which the runner's turns broadcast. Each
    # method holds the core lock from when it is called until it returns,
    # but while it waits; so does what it does once a wait is over, so that
    # no event taken by another thread in between is missed.
    #
    # The events of the connection are taken before each wait is looked at
    # again. What the Session keeps of a stream goes once the application
    # is done with both its parts. A protocol over the connection, HTTP/3,
    # is attached to the Session and called under the lock; the blocks of
    # `wait_for` are too, and are not to wait.
    #
    # `connection` is the QUIC connection behind a lock: each of its methods
    # is called holding the core lock. What one of them returns is read
    # without it, and may change.
    #
    # A client's Session keeps the tickets and the NEW_TOKEN tokens the
    # server gives (Kept). When the server takes no 0-RTT, each Stream the
    # client opened before raises QUIC::Error::ZeroRttRejected.
    #
    # `each_stream` starts a thread ("raiha-stream") for each stream the
    # peer opens, once it has a place of `threads`, waiting for one while
    # the connection is open and the driver runs.
    class Session
      # The QUIC connection behind the core lock of its driver.
      class Locked < BasicObject
        def initialize(connection, driver)
          @connection = connection
          @driver = driver
        end

        def method_missing(name, ...)
          @driver.synchronize { @connection.__send__(name, ...) }
        end

        def respond_to_missing?(name, include_private = false) = @connection.respond_to?(name, include_private)
      end

      Track = Raiha::Runtime::Session::Track
      MAX_ACK_DELAY = Raiha::Runtime::Session::MAX_ACK_DELAY
      MAX_HELD = Kept::MAX_HELD

      # The qlog tracer of the connection, if it has one, which a protocol
      # records its own events with.
      attr_reader :tracer

      # At a client, the name of the server the connection is to, and what
      # Client.connect was given to resume. Both are nil at a server.
      attr_reader :server_name, :resumed

      def initialize(connection, driver, role:, threads:, tracer: nil, server_name: nil, resumed: nil)
        @connection = connection
        @locked = Locked.new(connection, driver)
        @tracer = tracer
        @server_name = server_name
        @resumed = resumed
        @driver = driver
        @threads = threads
        @role = role
        @changed = driver.new_cond
        @waiting = 0
        @tracks = {} #: Hash[Integer, Track]
        @incoming = [] #: Array[Integer]
        @peer_next = [0, 0, 0, 0]
        @aborted = nil #: StandardError?
        @stopping = false
        @stop_deadline = nil #: Float?
        @connected = nil #: Raiha::QUIC::Event::Connected?
        @protocol = nil #: _Protocol?
        @close_code = 0
        @kept = Kept.new(tracer)
        @generation = 0
        # Whether the connection has closed or the driver stopped, for what
        # waits for a place of `threads` to look at without the core lock.
        @ended = false
      end

      # The threads the application's code runs in, which a protocol's
      # take their places of too.
      attr_reader :threads

      # The QUIC connection, each of its methods called under the core
      # lock.
      def connection = @locked # steep:ignore

      # The QUIC connection itself, for a protocol that calls it holding the
      # core lock, as it does in its turn.
      def core = @connection

      # Holds the core lock around the block, for a protocol whose method
      # touches what the lock guards from its start to its end.
      def synchronize(&) = @driver.synchronize(&)

      # Whether the connection has closed or the driver stopped, read
      # without the lock by what waits for a place of `threads`.
      def ended? = @ended

      # Raises Error::Usage where this thread holds the core lock, before
      # the application's code runs on it: a thread that did would keep the
      # driver from running while it waits.
      def unlocked!
        raise Error::Usage, "the core lock of the driver is held where the application runs" if @driver.mon_owned?
      end

      def handshake = @driver.synchronize { @connected&.handshake }

      def tickets = @driver.synchronize { @kept.tickets }

      def tokens = @driver.synchronize { @kept.tokens }

      # Puts `protocol` over the connection, which then closes with its
      # `close_code` when no other is given. A handshake completed before is
      # told it with the Connected event it missed. A connection that has
      # closed takes none, and raises QUIC::ClosedError, as a handler's
      # thread may come to it after the peer has closed.
      def attach(protocol, close_code: @close_code)
        @driver.synchronize do
          aborted = @aborted and raise aborted
          reason = @connection.close_reason and raise Raiha::QUIC::ClosedError.new(reason)
          @protocol = protocol
          @close_code = close_code
          connected = @connected and protocol.take(connected, Driver.clock)
          changed
        end
      end

      # Has what the protocol or the application changed go out.
      def changed = @driver.changed

      # A new stream of `direction` for a protocol, which keeps it itself:
      # its ID, once the peer allows it.
      def open_stream_id(direction: :bidi)
        @driver.synchronize do
          stream_id = wait { @connection.open_stream(direction:) }
          changed
          stream_id
        end
      end

      # Calls the block until it gives something other than nil or "",
      # under the core lock, waiting for a change in between: for a
      # protocol's waits. With `deadline`, nil once the clock is past it;
      # with `drain`, a read gives what came before the connection closed.
      # steep picks no overload of `wait` for a block that gives T?.
      def wait_for(deadline: nil, drain: false) # steep:ignore
        @driver.synchronize { deadline ? wait(deadline:, drain:) { yield } : wait(drain:) { yield } }
      end

      # A new stream of `direction` (:bidi or :uni), once the peer allows it.
      def open_stream(direction: :bidi)
        @driver.synchronize do
          stream_id = wait { @connection.open_stream(direction:) }
          @tracks[stream_id] = Track.new(nil, nil, direction == :bidi, true)
          changed
          Stream.new(self, stream_id, @generation)
        end
      end

      # Waits, for `seconds` at most, until all the streams have sent has
      # been acknowledged; whether it has.
      def wait_acknowledged(seconds)
        @driver.synchronize { wait(deadline: Driver.clock + seconds) { @connection.stats.send_buffer_bytes.zero? || nil } || false }
      end

      # Closes the connection with the application's `error_code` once what
      # the streams sent is acknowledged, or three PTOs have gone, unless it
      # has closed already.
      def close_when_acknowledged(error_code: @close_code)
        @driver.synchronize do
          next if closed?
          stats = @connection.stats
          wait_acknowledged(3 * (stats.rtt + [4 * stats.rtt_var, 0.001].max + MAX_ACK_DELAY))
          close(error_code:)
        end
      end

      def wait_handshake
        @driver.synchronize { wait { @connection.handshake_complete? || nil } }
        nil
      end

      # Waits until the application may send: until the handshake has
      # completed, or not at all while 0-RTT goes.
      def wait_ready
        @driver.synchronize { wait { @connection.handshake_complete? || @connection.zero_rtt_state == :pending || nil } }
        nil
      end

      # The next stream the peer opens; nil once the connection has closed,
      # or the server is stopping and none has come.
      def accept_stream
        @driver.synchronize do
          stream_id = wait(drain: true) { @incoming.shift || (:stopping if @stopping) }
          Stream.new(self, stream_id, @generation) unless stream_id == :stopping
        end
      rescue Raiha::QUIC::ClosedError
        nil
      end

      # Each stream the peer opens, in a thread of its own once a place is
      # free, until the connection closes or the server stops. A stream
      # whose thread cannot be started is reset, and stopped, with the
      # close code, and the ThreadError raised.
      def each_stream(&block)
        unlocked!
        while @threads.take { @ended }
          stream = accept_stream
          unless stream
            @threads.give_back
            break
          end
          start_stream(stream, &block)
        end
      end

      # Closes the connection with the application's `error_code`.
      def close(error_code: @close_code, reason: "")
        @driver.synchronize do
          @connection.close(error_code:, reason:, application: true, now: Driver.clock)
          changed
          notify
          ended
        end
      end

      def closed? = @driver.synchronize { !(@aborted || @connection.close_reason).nil? }

      def stopping? = @driver.synchronize { @stopping }

      def stop_deadline = @driver.synchronize { @stop_deadline }

      # The server is stopping, and closes what is left at `deadline`: what
      # waits for a stream to come wakes.
      def stopping!(deadline = nil)
        @driver.synchronize do
          @stopping = true
          @stop_deadline = deadline
          notify
        end
      end

      # The server is out of time to stop: the protocol is told, what it
      # sent goes, and the connection closes with `error_code`.
      def expire(error_code:)
        @driver.synchronize do
          next if closed?
          @protocol&.expire
          @driver.flush
          close(error_code:)
        end
      end

      # The driver has stopped, after `failure` when something failed in
      # it: what waits wakes to raise it, or QUIC::ClosedError.
      def abort(failure = nil)
        @driver.synchronize do
          @aborted ||= failure || Raiha::QUIC::ClosedError.new(Raiha::QUIC::ConnectionError.new(
            code: Raiha::QUIC::ErrorCode::NO_ERROR, frame_type: nil, reason: "the runtime stopped", application: false))
          notify
          ended
        end
      end

      # The runner's turn, under the core lock: the events are taken, and
      # what waits looks again.
      def turn
        take_events
        notify if @waiting.positive?
        ended if closed?
      end

      # Up to `max_bytes` of `stream_id` once there are any, nil at its
      # end, and after it.
      def read(stream_id, max_bytes, generation:)
        @driver.synchronize do
          current!(stream_id, generation)
          track = @tracks[stream_id]
          next nil unless track&.reading
          data = wait(drain: true) do
            current!(stream_id, generation)
            if (reset = track.reset)
              over(stream_id, :reading)
              raise StreamReset.new(stream_id, reset)
            end
            @connection.stream_read(stream_id, max_bytes) || :end
          end
          if data.is_a?(String)
            # What was read frees the peer's flow control, which the runner
            # tells it of; asleep since before the read, it would wait for
            # no more and the peer stay held back.
            changed
            next data
          end
          over(stream_id, :reading)
          nil
        end
      end

      # Writes all of `data` to `stream_id`, waiting for room as it goes,
      # and ends it with `fin`.
      def write(stream_id, data, fin:, generation:)
        @driver.synchronize do
          current!(stream_id, generation)
          track = @tracks[stream_id]
          raise Raiha::QUIC::Error::StreamError, "stream #{stream_id} has ended" unless track&.writing
          written = 0
          wait do
            current!(stream_id, generation)
            if (stopped = track.stop)
              over(stream_id, :writing)
              raise StreamReset.new(stream_id, stopped)
            end
            taken = @connection.stream_write(stream_id, data.byteslice(written..) || "".b, fin:)
            written += taken
            # A write that took nothing has nothing to send; the runner
            # woken for it would wake this thread again, and round they
            # would go.
            changed if taken.positive? || data.empty?
            written if written == data.bytesize
          end
          over(stream_id, :writing) if fin
          written
        end
      end


      # The thread of `stream`, which it is given apart from the loop of
      # each_stream that goes on to the next.
      private def start_stream(stream)
        @threads.start("raiha-stream") do
          unlocked!
          yield stream
        end
      rescue ThreadError
        give_up(stream.id)
        raise
      end

      # A stream no thread could be started for: it is let go both ways.
      private def give_up(stream_id)
        @driver.synchronize do
          @connection.stream_reset(stream_id, error_code: @close_code)
          @connection.stream_stop_sending(stream_id, error_code: @close_code)
          @tracks.delete(stream_id)
          changed
        end
      rescue Raiha::QUIC::Error::Base
        nil
      end

      # The connection has closed or the driver stopped: what waits for a
      # place of `threads` is to stop waiting.
      private def ended
        return if @ended
        @ended = true
        @threads.wake
      end

      private def take_events
        protocol = @protocol
        now = Driver.clock
        @connection.each_event do |event|
          zero_rtt_rejected if event.is_a?(Raiha::QUIC::Event::ZeroRttRejected)
          take(event) unless protocol&.take(event, now)
        end
        protocol&.turn(now)
      end

      private def zero_rtt_rejected
        @generation += 1
        @tracks.delete_if { |stream_id, _| local?(stream_id) }
        @connection.acknowledge_zero_rtt_rejection
      end

      private def current!(stream_id, generation)
        return if generation == @generation || !local?(stream_id)
        raise Raiha::QUIC::Error::ZeroRttRejected, "stream #{stream_id} went in 0-RTT, which the server rejected"
      end

      private def take(event)
        case event
        when Raiha::QUIC::Event::Connected then @connected = event
        when Raiha::QUIC::Event::StreamReadable then arrived(event.stream_id)
        when Raiha::QUIC::Event::StreamReset
          arrived(event.stream_id)
          @tracks[event.stream_id]&.reset = event.error_code
          forget_reset(event.stream_id)
        when Raiha::QUIC::Event::StopSending then @tracks[event.stream_id]&.stop = event.error_code
        when Raiha::QUIC::Event::SessionTicket then @kept.ticket(event.session)
        when Raiha::QUIC::Event::NewToken then @kept.token(event.token)
        end
      end

      private def arrived(stream_id)
        return if local?(stream_id)
        type = stream_id & 0x3
        while @peer_next.fetch(type) <= stream_id >> 2
          opened = @peer_next.fetch(type) << 2 | type
          @tracks[opened] = Track.new(nil, nil, true, opened.nobits?(0x2))
          @incoming << opened
          @peer_next[type] = @peer_next.fetch(type) + 1
        end
      end

      private def forget_reset(stream_id)
        return unless stream_id.anybits?(0x2) && @incoming.delete(stream_id)
        @tracks.delete(stream_id)
      end

      private def over(stream_id, part)
        track = @tracks[stream_id] or return
        track[part] = false
        @tracks.delete(stream_id) unless track.reading || track.writing
      end

      private def local?(stream_id) = stream_id.anybits?(0x1) == (@role == :server)

      private def notify = @changed.broadcast

      # Calls the block until it gives something other than nil or "",
      # waiting on the Session's condition in between, which lets the core
      # lock go; what it gave, or nil once the clock is past `deadline`.
      # Once the connection has closed, raises QUIC::ClosedError, and once
      # the driver has stopped, what `abort` was given; with `drain`, the
      # block is called first all the same. The caller holds the core lock.
      private def wait(deadline: nil, drain: false)
        @waiting += 1
        loop do
          take_events
          result = yield if drain
          return result unless result.nil? || result == "" # steep:ignore
          aborted = @aborted and raise aborted
          reason = @connection.close_reason and raise Raiha::QUIC::ClosedError.new(reason)
          result = yield unless drain
          return result unless result.nil? || result == "" # steep:ignore
          left = deadline && deadline - Driver.clock
          return nil if left && left <= 0
          @changed.wait(left)
        end
      ensure
        @waiting -= 1
      end
    end

    # A stream of a Session, read and written as an IO would be, as the
    # Stream of fibers is. Two threads are not to read it, or write it, at
    # once.
    class Stream
      PIECE = Raiha::Runtime::Stream::PIECE

      attr_reader :id

      def initialize(session, id, generation)
        @session = session
        @id = id
        @generation = generation
      end

      # With `length`, up to that many bytes once there are any, nil at the
      # end; without, all until the end, "" when it has ended.
      def read(length = nil)
        return @session.read(@id, length, generation: @generation) if length
        data = "".b
        while (chunk = @session.read(@id, PIECE, generation: @generation))
          data << chunk
        end
        data
      end

      # Writes all of `data`, waiting while the peer's flow control holds it
      # back; its length.
      def write(data)
        @session.write(@id, data.b, fin: false, generation: @generation)
        data.bytesize
      end

      def <<(data)
        write(data)
        self
      end

      # Ends the sending part.
      def close_write
        @session.write(@id, "".b, fin: true, generation: @generation)
        nil
      end
    end
  end
end
