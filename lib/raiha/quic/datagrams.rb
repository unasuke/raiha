# frozen_string_literal: true

module Raiha::QUIC
  # The DATAGRAM frames of a connection (RFC 9221): those the application
  # gave to send, and those received that it has not taken yet.
  #
  # A DATAGRAM goes only to a peer that took them in its transport
  # parameters, no larger than it said, and is never sent again. Those
  # waiting go in order of urgency, the lowest first, as RFC 9218 counts
  # it, and one past its `expires_at` is dropped unsent (RFC 9221
  # "Congestion Control"); when MAX_SEND_QUEUE wait, the application is
  # told no, and nothing waiting is dropped to make room.
  #
  # One received when this end did not take them, or larger than it said,
  # is PROTOCOL_VIOLATION. Its data is copied out of the packet and comes to
  # the application as Event::DatagramReceived; while MAX_RECEIVED of them,
  # or MAX_RECEIVED_BYTES, have not been taken, those that come are dropped,
  # as a receiver may (RFC 9221 "Flow Control"), since the application not
  # taking them is no fault of the peer's.
  class Datagrams
    MAX_SEND_QUEUE = 32
    MAX_RECEIVED = 128
    MAX_RECEIVED_BYTES = 1024 * 1024
    FRAME_TYPE = Wire::Frame::Datagram::TYPES.fetch(0)

    # One waiting to go.
    Waiting = Data.define(:data, :expires_at, :urgency)

    def initialize(config:, events:)
      @max_frame_size = config.max_datagram_frame_size || 0
      @events = events
      @queue = [] #: Array[Waiting]
      @received = 0
      @received_bytes = 0
    end

    # Queues `data` to send, of `max_size` bytes at most: whether it was.
    def send(data, expires_at:, urgency:, max_size:)
      return false if max_size.nil? || data.bytesize > max_size || @queue.size >= MAX_SEND_QUEUE
      waiting = Waiting.new(data: "".b << data, expires_at:, urgency:)
      index = @queue.index { |queued| queued.urgency > urgency } || @queue.size
      @queue.insert(index, waiting)
      true
    end

    # The urgency of the DATAGRAM to go next, nil when none waits; those
    # expired at `now` are dropped.
    def urgency(now:)
      drop_expired(now)
      @queue.first&.urgency
    end

    # The next DATAGRAM frame to send in no more than `room` bytes, nil when
    # none waits or the next does not fit; those expired at `now` are
    # dropped.
    def next_frame(room, now:)
      drop_expired(now)
      head = @queue.first or return nil
      frame = Wire::Frame::Datagram.new(data: head.data)
      return nil if Wire::Frame.encode([frame], ack_delay_exponent: 0).bytesize > room
      @queue.shift
      frame
    end

    # Takes a DATAGRAM frame from the peer.
    # A client's 0-RTT was rejected: what waits to go was written for it,
    # and goes no more (RFC 9001 "Accepting and Rejecting 0-RTT").
    def drop_queued = @queue.clear

    def receive(frame)
      size = frame.data.bytesize
      raise Violation.new("a DATAGRAM frame, which this end did not take", frame_type: FRAME_TYPE) if @max_frame_size.zero?
      raise Violation.new("a DATAGRAM frame over #{@max_frame_size} bytes", frame_type: FRAME_TYPE) if 1 + size > @max_frame_size
      return if @received >= MAX_RECEIVED || @received_bytes + size > MAX_RECEIVED_BYTES
      @received += 1
      @received_bytes += size
      @events << Event::DatagramReceived.new(data: "".b << frame.data)
    end

    # The application took `event` from the connection.
    def taken(event)
      return unless event.is_a?(Event::DatagramReceived)
      @received -= 1
      @received_bytes -= event.data.bytesize
    end

    private def drop_expired(now)
      @queue.shift while (head = @queue.first) && (expires_at = head.expires_at) && expires_at <= now
    end
  end
end
