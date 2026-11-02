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
  # when it does, raises QUIC::ClosedError, and so does one once the driver
  # has stopped, or what failed in it.
  #
  # The events of the connection are taken before each wait is looked at
  # again, so that a stream the peer reset is not read to an end it never
  # sent. What the Session keeps of a stream goes once the application is
  # done with both its parts, and of the streams the peer opened it keeps
  # the next to come of each type, so a long connection keeps no more than
  # the streams open on it.
  #
  # A protocol over the connection, HTTP/3, is attached to the Session: it
  # takes each event first, keeping those of its own, and takes its turn
  # after them, and the streams it opens are its own to keep.
  #
  # A client's Session keeps the tickets and the NEW_TOKEN tokens the
  # server gives, for later connections; storing them is the
  # application's.
  class Session
    # What the application has yet to hear of a stream: how the peer reset
    # its sending part or stopped ours, and whether each part is still in
    # use.
    Track = Struct.new(:reset, :stop, :reading, :writing)
    # The peer's max_ack_delay when it says none (RFC 9000 "Transport
    # Parameter Definitions"), for a PTO of the connection.
    MAX_ACK_DELAY = 0.025
    # The most tickets and tokens kept: one more drops the oldest, so that a
    # server sending them without end cannot make the client keep them all.
    MAX_HELD = 8

    # The connection, and the qlog tracer of it, if it has one, which a
    # protocol records its own events with.
    attr_reader :connection, :tracer

    def initialize(connection, driver, role:, tracer: nil)
      @connection = connection
      @tracer = tracer
      @driver = driver
      @role = role
      @lock = Thread::Mutex.new
      @changed = Thread::ConditionVariable.new
      @waiting = 0
      @tracks = {} #: Hash[Integer, Track]
      # The streams the peer opened and the application has not taken, and
      # the index of the next to come of each type of stream ID.
      @incoming = [] #: Array[Integer]
      @peer_next = [0, 0, 0, 0]
      @aborted = nil #: StandardError?
      @stopping = false
      @stop_deadline = nil #: Float?
      @connected = nil #: Raiha::Next::QUIC::Event::Connected?
      @protocol = nil #: _Protocol?
      # The application's error code a close with none given closes with.
      @close_code = 0
      @tickets = [] #: Array[Raiha::Next::QUIC::Session]
      @tokens = [] #: Array[String]
    end

    # What the handshake came to (TLS::Event::HandshakeComplete), once it
    # has completed.
    def handshake = @connected&.handshake

    # The tickets the server gave, each a QUIC::Session for
    # Client.connect(session:), the newest MAX_HELD of them, newest last. A
    # ticket is for one connection: once used, the application drops it,
    # as one used again links the connections for those who watch (RFC 9846
    # "Client and Server Tracking Prevention").
    def tickets = @tickets.dup

    # The tokens the server gave in NEW_TOKEN frames, for
    # Client.connect(token:), the newest MAX_HELD of them, newest last. A
    # token is for one connection too (RFC 9000 "Address Validation for
    # Future Connections").
    def tokens = @tokens.dup

    # Puts `protocol` over the connection, which then closes with its
    # `close_code` when no other is given: H3_NO_ERROR for HTTP/3, say. A
    # handshake completed before is told it with the Connected event it
    # missed.
    def attach(protocol, close_code: @close_code)
      @protocol = protocol
      @close_code = close_code
      connected = @connected and protocol.take(connected, Driver.clock)
      changed
    end

    # Has what the protocol or the application changed go out.
    def changed = @driver.changed

    # A new stream of `direction` for a protocol, which keeps it itself: its
    # ID, once the peer allows it.
    def open_stream_id(direction: :bidi)
      stream_id = wait { @connection.open_stream(direction:) }
      changed
      stream_id
    end

    # Calls the block until it gives something other than nil or "",
    # waiting for a change in between, as `wait` does: for a protocol's
    # waits. With `deadline`, nil once the clock is past it; with `drain`, a
    # read gives what came before the connection closed.
    # steep picks no overload of `wait` for a block that gives T?.
    def wait_for(deadline: nil, drain: false) # steep:ignore
      deadline ? wait(deadline:, drain:) { yield } : wait(drain:) { yield }
    end

    # A new stream of `direction` (:bidi or :uni), once the peer allows it.
    def open_stream(direction: :bidi)
      stream_id = wait { @connection.open_stream(direction:) }
      @tracks[stream_id] = Track.new(nil, nil, direction == :bidi, true)
      @driver.changed
      Stream.new(self, stream_id)
    end

    # Waits, for `seconds` at most, until all the streams have sent has been
    # acknowledged; whether it has. A connection closed meanwhile raises
    # QUIC::ClosedError.
    def wait_acknowledged(seconds)
      wait(deadline: Driver.clock + seconds) { @connection.stats.send_buffer_bytes.zero? || nil } || false
    end

    # Closes the connection with the application's `error_code` once what the
    # streams sent is acknowledged, or three PTOs have gone, unless it has
    # closed already.
    def close_when_acknowledged(error_code: @close_code)
      return if closed?
      stats = @connection.stats
      wait_acknowledged(3 * (stats.rtt + [4 * stats.rtt_var, 0.001].max + MAX_ACK_DELAY))
      close(error_code:)
    end

    # Waits until the handshake has completed.
    def wait_handshake
      wait { @connection.handshake_complete? || nil }
      nil
    end

    # The next stream the peer opens; nil once the connection has closed, or
    # the server is stopping and none has come.
    def accept_stream
      stream_id = wait(drain: true) { @incoming.shift || (:stopping if @stopping) }
      Stream.new(self, stream_id) unless stream_id == :stopping
    rescue Raiha::Next::QUIC::ClosedError
      nil
    end

    # Each stream the peer opens, in a fiber of its own, until the
    # connection closes or the server stops.
    def each_stream
      while (stream = accept_stream)
        Fiber.schedule { yield stream }
      end
    end

    # Closes the connection with the application's `error_code`.
    def close(error_code: @close_code, reason: "")
      @connection.close(error_code:, reason:, application: true, now: Driver.clock)
      @driver.changed
      notify
    end

    def closed? = !(@aborted || @connection.close_reason).nil?

    # Whether the server is stopping: the application is to end the
    # connection soon.
    def stopping? = @stopping

    # When the server will close what is left, while it is stopping.
    attr_reader :stop_deadline

    # The server is stopping, and closes what is left at `deadline`: what
    # waits for a stream to come wakes.
    def stopping!(deadline = nil)
      @stopping = true
      @stop_deadline = deadline
      notify
    end

    # The server is out of time to stop: the protocol is told, what it
    # sent goes, and the connection closes with `error_code` without
    # waiting for anything to be acknowledged.
    def expire(error_code:)
      return if closed?
      @protocol&.expire
      @driver.flush
      close(error_code:)
    end

    # The driver has stopped, after `failure` when something failed in it:
    # nothing more comes or goes, and what waits wakes to raise it, or
    # QUIC::ClosedError.
    def abort(failure = nil)
      @aborted ||= failure || Raiha::Next::QUIC::ClosedError.new(Raiha::Next::QUIC::ConnectionError.new(
        code: Raiha::Next::QUIC::ErrorCode::NO_ERROR, frame_type: nil, reason: "the runtime stopped", application: false))
      notify
    end

    # The runner's turn: the events are taken, and what waits looks again,
    # as a limit the peer raised comes with no event.
    def turn
      take_events
      notify if @waiting.positive?
    end

    # Up to `max_bytes` of `stream_id` once there are any, nil at its end,
    # and after it.
    def read(stream_id, max_bytes)
      track = @tracks[stream_id]
      return nil unless track&.reading
      data = wait(drain: true) do
        if (reset = track.reset)
          over(stream_id, :reading)
          raise StreamReset.new(stream_id, reset)
        end
        @connection.stream_read(stream_id, max_bytes) || :end
      end
      return data if data.is_a?(String)
      over(stream_id, :reading)
      nil
    end

    # Writes all of `data` to `stream_id`, waiting for room as it goes, and
    # ends it with `fin`.
    def write(stream_id, data, fin:)
      track = @tracks[stream_id]
      raise Raiha::Next::QUIC::Error::StreamError, "stream #{stream_id} has ended" unless track&.writing
      written = 0
      wait do
        if (stopped = track.stop)
          over(stream_id, :writing)
          raise StreamReset.new(stream_id, stopped)
        end
        taken = @connection.stream_write(stream_id, data.byteslice(written..) || "".b, fin:)
        written += taken
        # A write that took nothing has nothing to send; the runner woken
        # for it would wake this fiber again, and round they would go.
        @driver.changed if taken.positive? || data.empty?
        written if written == data.bytesize
      end
      over(stream_id, :writing) if fin
      written
    end

    private def take_events
      protocol = @protocol
      now = Driver.clock
      @connection.each_event { |event| take(event) unless protocol&.take(event, now) }
      protocol&.turn(now)
    end

    private def take(event)
      case event
      when Raiha::Next::QUIC::Event::Connected then @connected = event
      when Raiha::Next::QUIC::Event::StreamReadable then arrived(event.stream_id)
      when Raiha::Next::QUIC::Event::StreamReset
        arrived(event.stream_id)
        @tracks[event.stream_id]&.reset = event.error_code
        forget_reset(event.stream_id)
      when Raiha::Next::QUIC::Event::StopSending then @tracks[event.stream_id]&.stop = event.error_code
      when Raiha::Next::QUIC::Event::SessionTicket then ticket(event.session)
      when Raiha::Next::QUIC::Event::NewToken
        @tokens.shift if @tokens.size >= MAX_HELD
        @tokens << event.token
      end
    end

    private def ticket(session)
      if @tickets.size >= MAX_HELD
        @tickets.shift
        @tracer&.tls_trace(Raiha::Next::TLS::Trace::TicketIgnored.new(reason: :too_many_tickets))
      end
      @tickets << session
    end

    # A stream the peer opened comes to be known from its first event, and
    # so do those of its type below it, which it opened with it (RFC 9000
    # "Stream Concurrency").
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

    # A stream going one way the peer reset before the application took it
    # has nothing for it: the core has let it go and lets the peer open
    # another, so keeping it would let the peer grow what is kept without
    # end.
    private def forget_reset(stream_id)
      return unless stream_id.anybits?(0x2) && @incoming.delete(stream_id)
      @tracks.delete(stream_id)
    end

    # The application is done with a part of `stream_id`; once with both,
    # the Session forgets it.
    private def over(stream_id, part)
      track = @tracks[stream_id] or return
      track[part] = false
      @tracks.delete(stream_id) unless track.reading || track.writing
    end

    private def local?(stream_id) = stream_id.anybits?(0x1) == (@role == :server)

    private def notify = @lock.synchronize { @changed.broadcast }

    # Calls the block until it gives something other than nil or "", waiting
    # for a change in between; what it gave, or nil once the clock is past
    # `deadline`. Once the connection has closed, raises QUIC::ClosedError, and
    # once the driver has stopped, what `abort` was given; with `drain`, the
    # block is called first all the same, so what came before the close is
    # still given.
    private def wait(deadline: nil, drain: false)
      @lock.synchronize do
        @waiting += 1
        loop do
          take_events
          result = yield if drain
          # T is within T | nil; steep loses it across the two signatures.
          return result unless result.nil? || result == "" # steep:ignore
          aborted = @aborted and raise aborted
          reason = @connection.close_reason and raise Raiha::Next::QUIC::ClosedError.new(reason)
          result = yield unless drain
          return result unless result.nil? || result == "" # steep:ignore
          left = deadline && deadline - Driver.clock
          return nil if left && left <= 0
          @changed.wait(@lock, left)
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
