# frozen_string_literal: true

module Raiha::Next::Runtime
  # The peer reset the stream a read waits on, or stopped the one a write
  # goes to, with `error_code`.
  class StreamReset < StandardError
    attr_reader :stream_id, :error_code

    def initialize(stream_id, error_code)
      @stream_id = stream_id
      @error_code = error_code
      super(format("stream %d was reset with 0x%x", stream_id, error_code))
    end
  end

  # A QUIC connection the fibers of the application use as if it blocked:
  # a read waits for data, a write for room, an open for a stream the peer
  # allows, each on the condition of the connection, which its Driver's
  # turns signal. A call made once the connection has closed, or waiting
  # when it does, raises QUIC::ClosedError.
  #
  # The events of the connection are taken before each wait is looked at
  # again, so that a stream the peer reset is not read to an end it never
  # sent.
  class Session
    attr_reader :connection

    def initialize(connection, driver, role:)
      @connection = connection
      @driver = driver
      @role = role
      @lock = Thread::Mutex.new
      @changed = Thread::ConditionVariable.new
      @waiting = 0
      # The streams the peer opened and the application has not taken.
      @incoming = [] #: Array[Integer]
      @known = {} #: Hash[Integer, true]
      # How the peer reset the sending part of a stream, or stopped ours.
      @resets = {} #: Hash[Integer, Integer]
      @stops = {} #: Hash[Integer, Integer]
    end

    # A new stream of `direction` (:bidi or :uni), once the peer allows it.
    def open_stream(direction: :bidi)
      stream_id = wait { @connection.open_stream(direction:) }
      @known[stream_id] = true
      @driver.changed
      Stream.new(self, stream_id)
    end

    # The next stream the peer opens; nil once the connection has closed.
    def accept_stream
      Stream.new(self, wait { @incoming.shift })
    rescue Raiha::Next::QUIC::ClosedError
      nil
    end

    # Each stream the peer opens, in a fiber of its own, until the
    # connection closes.
    def each_stream
      while (stream = accept_stream)
        Fiber.schedule { yield stream }
      end
    end

    # Closes the connection with the application's `error_code`.
    def close(error_code: 0, reason: "")
      @connection.close(error_code:, reason:, application: true, now: Driver.clock)
      @driver.changed
      notify
    end

    def closed? = !@connection.close_reason.nil?

    # The runner's turn: the events are taken, and what waits looks again,
    # as a limit the peer raised comes with no event.
    def turn
      take_events
      notify if @waiting.positive?
    end

    # Up to `max_bytes` of `stream_id` once there are any, nil at its end.
    def read(stream_id, max_bytes)
      data = wait do
        reset = @resets[stream_id] and raise StreamReset.new(stream_id, reset)
        @connection.stream_read(stream_id, max_bytes) || :end
      end
      data unless data == :end
    end

    # Writes all of `data` to `stream_id`, waiting for room as it goes, and
    # ends it with `fin`.
    def write(stream_id, data, fin:)
      written = 0
      wait do
        stopped = @stops[stream_id] and raise StreamReset.new(stream_id, stopped)
        written += @connection.stream_write(stream_id, data.byteslice(written..) || "".b, fin:)
        @driver.changed
        written if written == data.bytesize
      end
    end

    private def take_events
      @connection.each_event { |event| take(event) }
    end

    private def take(event)
      case event
      when Raiha::Next::QUIC::Event::StreamReadable then arrived(event.stream_id)
      when Raiha::Next::QUIC::Event::StreamReset then @resets[arrived(event.stream_id)] = event.error_code
      when Raiha::Next::QUIC::Event::StopSending then @stops[event.stream_id] = event.error_code
      end
    end

    # A stream the peer opened is known from its first event.
    private def arrived(stream_id)
      unless @known.key?(stream_id) || local?(stream_id)
        @known[stream_id] = true
        @incoming << stream_id
      end
      stream_id
    end

    private def local?(stream_id) = stream_id.anybits?(0x1) == (@role == :server)

    private def notify = @lock.synchronize { @changed.broadcast }

    # Calls the block until it gives something other than nil or "", waiting
    # for a change in between; what it gave. Once the connection has closed,
    # raises QUIC::ClosedError.
    private def wait
      @lock.synchronize do
        @waiting += 1
        loop do
          take_events
          reason = @connection.close_reason and raise Raiha::Next::QUIC::ClosedError.new(reason)
          result = yield
          return result unless result.nil? || result == ""
          @changed.wait(@lock)
        end
      ensure
        @waiting -= 1
      end
    end
  end

  # A stream of a Session, read and written as an IO would be.
  class Stream
    # The most a read with no length asks for at a time.
    PIECE = 65_536

    attr_reader :id

    def initialize(session, id)
      @session = session
      @id = id
    end

    # With `length`, up to that many bytes once there are any, nil at the
    # end; without, all until the end, "" when it has ended.
    def read(length = nil)
      return @session.read(@id, length) if length
      data = "".b
      while (chunk = @session.read(@id, PIECE))
        data << chunk
      end
      data
    end

    # Writes all of `data`, waiting while the peer's flow control holds it
    # back; its length.
    def write(data)
      @session.write(@id, data.b, fin: false)
      data.bytesize
    end

    def <<(data)
      write(data)
      self
    end

    # Ends the sending part.
    def close_write
      @session.write(@id, "".b, fin: true)
      nil
    end
  end
end
