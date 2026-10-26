# frozen_string_literal: true

module Raiha::Next::QUIC
  # The streams of a connection and their flow control (RFC 9000 "Streams"
  # and "Flow Control"): the receiving and sending parts of each stream,
  # the connection's receive window, and the limits on how many streams
  # each end opens.
  #
  # A stream ID tells who opened the stream and which way it goes; a frame
  # for a part the stream does not have, or for a stream of this end not
  # opened yet, is STREAM_STATE_ERROR, and a stream of the peer past the
  # limit given STREAM_LIMIT_ERROR. A stream of the peer opens with the
  # first frame for it, and with it those of the same kind numbered below
  # it (RFC 9000 "Stream Types and Identifiers").
  #
  # A STREAM frame is checked before any of its data is kept: the
  # stream's ID, its final size, its limit, then the connection's limit,
  # in that order, so that the first rule broken names the error (flow
  # control's design, "Detecting Violations"). The connection has received
  # the sum of how far each stream has, counted however the data has
  # gaps (CVE-2026-75804). The holes of all the streams together are at
  # most one for each datagram the connection's largest receive window
  # holds, past which the connection closes with INTERNAL_ERROR rather
  # than dropping data an ACK has already covered: a peer that sends in
  # bursts loses up to every other datagram when a queue overflows, which
  # stays under it, and holes of a byte each stay some thirteen thousand
  # pieces with the default window.
  #
  # A stream that had nothing to read and has now tells the application
  # with Event::StreamReadable, once, as the application reads it until it
  # gives "" or nil. Credit goes back as MAX_DATA and MAX_STREAM_DATA as
  # the data is read; a stream's window that grows takes the connection's
  # to one and a half times it at least, so that one stream cannot use up
  # the connection's window.
  #
  # Sending, a write takes what the stream's credit, the connection's and
  # this end's send buffer, max_send_buffer bytes of data not sent or not
  # acknowledged, all leave room for, and no more; a stream written less
  # than asked tells the application with Event::StreamWritable, once,
  # when it can take some again (flow control's design, "Sending"). A
  # write the peer's credit cuts short, or a stream the peer's limit keeps
  # from opening, sends DATA_BLOCKED, STREAM_DATA_BLOCKED or
  # STREAMS_BLOCKED with the limit, once for each value of it; one this
  # end's send buffer cuts short sends none. The tracer hears when the
  # peer's credit blocks the connection or a stream, and when it no longer
  # does. Frames are taken from the streams with something to send in the
  # order the Scheduler keeps, one a time.
  #
  # The application stops reading a stream with STOP_SENDING, or resets
  # one it writes with RESET_STREAM; a peer's STOP_SENDING resets the
  # stream with its error code (RFC 9000 "Solicited State Transitions").
  # What a stream abandoned on either end held goes back to the
  # connection's window at once, and its receiving part gets no more
  # credit.
  #
  # A stream whose parts are both over, read to the end or reset, and
  # acknowledged to the end or reset and acknowledged, is let go: frames
  # for it are ignored and a read gives its end. One of the peer's makes
  # room for another, so that the peer can keep as many open at once as
  # the limit first given; MAX_STREAMS tells it when the room not told
  # yet is an eighth of that limit, at least one (flow control's design,
  # "Stream Limits"). STREAMS_BLOCKED does not hurry it, as a peer always
  # at the limit would otherwise get MAX_STREAMS for every stream or two
  # that ends, as quinn and quic-go do not.
  class Streams
    # The low bits of a stream ID: who opened it, and which way it goes.
    SERVER_INITIATED = 0x01
    UNIDIRECTIONAL = 0x02
    # How much wider than a stream's window the connection's is kept.
    CONNECTION_WINDOW_FACTOR = 1.5
    # The longest a limit takes as a varint: a credit frame is put together
    # only where it fits with that, as its value is fixed as it goes.
    MAX_VARINT_SIZE = 8
    # The share of the streams the peer may have open at once that, not
    # told yet, makes MAX_STREAMS due.
    STREAM_CREDIT_SHARE = 8
    DIRECTIONS = %i[bidi uni].freeze

    # The connection's receive window.
    attr_reader :window
    # The holes the data received may have, all the streams together.
    attr_reader :max_gaps
    # The stream data not sent or not acknowledged.
    attr_reader :buffered
    # How many BLOCKED frames the peer's limits made this end send, not
    # counting those sent again, and how many the peer sent.
    attr_reader :blocked_sent
    attr_reader :blocked_received

    # Events go to `events`.
    def initialize(role:, config:, events:, now:, tracer: nil)
      @role = role
      @config = config
      @events = events
      @tracer = tracer
      @window = ReceiveWindow.new(size: config.initial_max_data, max: config.max_receive_window, now:)
      @receivers = {} #: Hash[Integer, Receiver]
      @senders = {} #: Hash[Integer, Sender]
      # How many streams of each type (the low two bits of an ID) are open.
      @opened = [0, 0, 0, 0]
      @gaps = 0
      @max_gaps = config.max_receive_window / config.initial_max_datagram_size
      @peer_parameters = nil #: TransportParameters?
      # What the peer allows this end to send on the connection, and how
      # much it has written; the bytes not acknowledged, of all the streams.
      @peer_max_data = 0
      @written = 0
      @buffered = 0
      # How many streams of each direction the peer allows this end to open.
      @peer_max_streams = { bidi: 0, uni: 0 }
      # The streams with something to send, in the order they take turns,
      # and those written less than asked.
      @scheduler = Scheduler.new
      @wanting = [] #: Array[Integer]
      # The limits a DATA_BLOCKED and a STREAMS_BLOCKED of each direction
      # are due or went for, and which are due.
      @data_blocked_at = nil #: Integer?
      @data_blocked_due = false
      @streams_blocked_at = { bidi: nil, uni: nil } #: Hash[:bidi | :uni, Integer?]
      @streams_blocked_due = { bidi: false, uni: false }
      # How many streams of each direction the peer may open, as last told;
      # how many of its streams are over; and whether MAX_STREAMS goes
      # again.
      @local_max_streams = { bidi: config.initial_max_streams_bidi, uni: config.initial_max_streams_uni }
      @ended = { bidi: 0, uni: 0 }
      @max_streams_resend = { bidi: false, uni: false }
      @blocked_sent = 0
      @blocked_received = 0
      # Whether the peer's credit blocks the connection, and the streams it
      # blocks.
      @connection_blocked = false
      @flow_blocked = [] #: Array[Integer]
    end

    # The peer's transport parameters, which set the limits of what this
    # end sends.
    def peer_parameters=(parameters)
      @peer_parameters = parameters
      @peer_max_data = parameters.initial_max_data
      @peer_max_streams = { bidi: parameters.initial_max_streams_bidi, uni: parameters.initial_max_streams_uni }
    end

    # Opens a stream of this end going `direction`, :bidi or :uni: its ID,
    # or nil when the peer allows no more.
    def open(direction, now:)
      type = (@role == :server ? SERVER_INITIATED : 0) | (direction == :uni ? UNIDIRECTIONAL : 0)
      index = @opened.fetch(type)
      limit = @peer_max_streams.fetch(direction)
      return streams_blocked(direction, limit) if index >= limit
      stream_id = index << 2 | type
      @opened[type] = index + 1
      peer = @peer_parameters or raise Error::StateError, "the peer's transport parameters have not come"
      if direction == :uni
        @senders[stream_id] = Sender.new(stream_id:, limit: peer.initial_max_stream_data_uni)
      else
        @senders[stream_id] = Sender.new(stream_id:, limit: peer.initial_max_stream_data_bidi_remote)
        window = ReceiveWindow.new(size: @config.initial_max_stream_data_bidi_local, max: @config.max_stream_receive_window, now:)
        @receivers[stream_id] = Receiver.new(window:)
      end
      stream_id
    end

    # Writes as much of `data` to `stream_id` as there is room for, and
    # the end of the stream with `fin` when all of it fits: how many bytes
    # were taken.
    def write(stream_id, data, fin:, now:)
      sender = sender_for(stream_id)
      accepted = [data.bytesize, room_for(sender)].min
      whole = accepted == data.bytesize
      taken = data.byteslice(0, accepted) #: String
      sender.write(taken, fin: fin && whole)
      @written += accepted
      @buffered += accepted
      @scheduler.ready(stream_id)
      unless whole
        @wanting << stream_id unless @wanting.include?(stream_id)
        stream_blocked(stream_id, now) if sender.credit.zero?
        data_blocked(now) if @written == @peer_max_data
      end
      accepted
    end

    # The application resets `stream_id` with `error_code`.
    def reset(stream_id, error_code)
      sender = @senders[stream_id]
      return if sender.nil? && over?(stream_id) && sends?(stream_id)
      sender or raise Error::StreamError, "stream #{stream_id} has nothing to write to"
      abandon_sending(sender, error_code)
    end

    # The application sends `stream_id` with `urgency` and as `incremental`
    # (RFC 9218), as the Scheduler orders the streams.
    def prioritize(stream_id, urgency:, incremental:)
      sender = @senders[stream_id]
      return if sender.nil? && over?(stream_id) && sends?(stream_id)
      sender or raise Error::StreamError, "stream #{stream_id} has nothing to write to"
      @scheduler.prioritize(stream_id, urgency:, incremental:)
    end

    # The application stops reading `stream_id`, asking the peer with
    # `error_code` to stop sending.
    def stop_sending(stream_id, error_code)
      receiver = @receivers[stream_id]
      return if receiver.nil? && over?(stream_id) && receives?(stream_id)
      receiver or raise Error::StreamError, "stream #{stream_id} has nothing to read"
      gaps = receiver.gaps
      consumed = receiver.stop!(error_code)
      @gaps -= gaps - receiver.gaps
      @window.consume(consumed)
      retire(stream_id)
    end

    # The peer reset a stream: checked as the end of data is, and the
    # application hears of it once.
    def receive_reset_stream(frame, now:)
      type = Wire::Frame::ResetStream::TYPES.fetch(0)
      receiver = receiver_for(frame.stream_id, frame_type: type, now:) or return
      grown = receiver.admit(frame.final_size, fin: true, frame_type: type)
      @window.receive(@window.received + grown, frame_type: type)
      return if receiver.reset?
      gaps = receiver.gaps
      @window.consume(receiver.reset!(frame.final_size))
      @gaps -= gaps
      @events << Event::StreamReset.new(stream_id: frame.stream_id, error_code: frame.error_code, final_size: frame.final_size)
      retire(frame.stream_id)
    end

    # The peer cannot open a stream past the limit told; MAX_STREAMS keeps
    # to its threshold all the same.
    def receive_streams_blocked(frame)
      @blocked_received += 1
    end

    # The peer asks this end to stop sending a stream: it is reset with
    # the same error code, and the application hears of it.
    def receive_stop_sending(frame, now:)
      sender = sender_part(frame.stream_id, frame_type: Wire::Frame::StopSending::TYPES.fetch(0), now:) or return
      @events << Event::StopSending.new(stream_id: frame.stream_id, error_code: frame.error_code)
      abandon_sending(sender, frame.error_code)
    end

    # The next RESET_STREAM or STOP_SENDING due and its duty, in no more
    # than `room` bytes; nil when none is or it does not fit.
    def next_abandon(room)
      @senders.each do |stream_id, sender|
        code = sender.reset_due or next
        frame = Wire::Frame::ResetStream.new(stream_id:, error_code: code, final_size: sender.final_size)
        return nil unless fits?(frame, room)
        sender.reset_sent
        return [frame, Recovery::Duty::ResetStream.new(stream_id:)]
      end
      @receivers.each do |stream_id, receiver|
        code = receiver.stop_due or next
        frame = Wire::Frame::StopSending.new(stream_id:, error_code: code)
        return nil unless fits?(frame, room)
        receiver.stop_sent
        return [frame, Recovery::Duty::StopSending.new(stream_id:)]
      end
      nil
    end

    def reset_stream_acked(duty)
      sender = @senders[duty.stream_id] or return
      sender.reset_acked
      retire(duty.stream_id)
    end

    def reset_stream_lost(duty) = @senders[duty.stream_id]&.reset_lost

    def stop_sending_lost(duty) = @receivers[duty.stream_id]&.stop_lost

    # The peer's limits grew: what they now let through can be written.
    def receive_max_data(frame, now:)
      return unless frame.maximum > @peer_max_data
      @peer_max_data = frame.maximum
      if @connection_blocked
        @connection_blocked = false
        @tracer&.connection_data_blocked_updated(old: :blocked, new: :unblocked, reason: :connection_flow_control, now:)
      end
      writable_again
    end

    def receive_max_stream_data(frame, now:)
      sender = sender_part(frame.stream_id, frame_type: Wire::Frame::MaxStreamData::TYPES.fetch(0), now:) or return
      return unless sender.raise_limit(frame.maximum)
      if @flow_blocked.delete(frame.stream_id)
        @tracer&.stream_data_blocked_updated(stream_id: frame.stream_id, old: :blocked, new: :unblocked, reason: :stream_flow_control, now:)
      end
      writable_again
    end

    def receive_max_streams(frame)
      direction = frame.bidirectional ? :bidi : :uni #: :bidi | :uni
      @peer_max_streams[direction] = frame.maximum if frame.maximum > @peer_max_streams.fetch(direction)
    end

    # The peer is blocked by the connection's limit or a stream's: credit
    # not told yet goes at once.
    def receive_data_blocked(frame)
      @blocked_received += 1
      @window.blocked!
    end

    def receive_stream_data_blocked(frame, now:)
      @blocked_received += 1
      receiver = receiver_for(frame.stream_id, frame_type: Wire::Frame::StreamDataBlocked::TYPES.fetch(0), now:) or return
      receiver.window.blocked!
    end

    # The next DATA_BLOCKED, STREAMS_BLOCKED or STREAM_DATA_BLOCKED due and
    # its duty, in no more than `room` bytes; nil when none is or it does
    # not fit.
    def next_blocked(room)
      if @data_blocked_due
        frame = Wire::Frame::DataBlocked.new(maximum: @peer_max_data)
        return nil unless fits?(frame, room)
        @data_blocked_due = false
        return [frame, Recovery::Duty::DataBlocked.new(maximum: frame.maximum)]
      end
      @streams_blocked_due.each do |direction, due|
        next unless due
        bidirectional = direction == :bidi
        frame = Wire::Frame::StreamsBlocked.new(bidirectional:, maximum: @peer_max_streams.fetch(direction))
        return nil unless fits?(frame, room)
        @streams_blocked_due[direction] = false
        return [frame, Recovery::Duty::StreamsBlocked.new(bidirectional:, maximum: frame.maximum)]
      end
      @senders.each do |stream_id, sender|
        next unless sender.blocked_due?
        frame = Wire::Frame::StreamDataBlocked.new(stream_id:, maximum: sender.limit)
        return nil unless fits?(frame, room)
        sender.blocked_sent
        return [frame, Recovery::Duty::StreamDataBlocked.new(stream_id:, maximum: frame.maximum)]
      end
      nil
    end

    # A BLOCKED frame was lost: it goes again while its limit still holds
    # this end back.
    def data_blocked_lost(duty)
      @data_blocked_due = true if duty.maximum == @peer_max_data && @written == @peer_max_data
    end

    def stream_data_blocked_lost(duty) = @senders[duty.stream_id]&.blocked_lost(duty.maximum)

    def streams_blocked_lost(duty)
      direction = duty.bidirectional ? :bidi : :uni #: :bidi | :uni
      limit = @peer_max_streams.fetch(direction)
      type = (@role == :server ? SERVER_INITIATED : 0) | (duty.bidirectional ? 0 : UNIDIRECTIONAL)
      @streams_blocked_due[direction] = true if duty.maximum == limit && @opened.fetch(type) >= limit
    end

    # How many bytes a write to `stream_id` would take now.
    def writable_bytes(stream_id) = room_for(sender_for(stream_id))

    # The streams a write would take something on.
    def writable = @senders.filter_map { |stream_id, sender| stream_id if !sender.fin? && !sender.reset? && room_for(sender).positive? }

    # The next STREAM frame and its duty in no more than `room` bytes, from
    # the next stream in turn with something to send; nil when none has,
    # or the frame does not fit.
    def next_stream_frame(room)
      sender = current_sender or return nil
      pair = sender.next_frame(room) or return nil
      @scheduler.advance
      pair
    end

    # The urgency of the next stream in turn with something to send; nil
    # when none has.
    def urgency
      @scheduler.urgency if current_sender
    end

    # Data sent was acknowledged: the bytes let go leave room in the send
    # buffer.
    def stream_data_acked(duty)
      sender = @senders[duty.stream_id] or return
      @buffered -= sender.acked(duty.offset, duty.length, duty.fin)
      writable_again
      retire(duty.stream_id)
    end

    # Data sent was lost: it goes again.
    def stream_data_lost(duty)
      sender = @senders[duty.stream_id] or return
      sender.lost(duty.offset, duty.length, duty.fin)
      @scheduler.ready(duty.stream_id)
    end

    # Takes a STREAM frame: its data is kept, once every check passes.
    def receive_stream(frame, now:)
      type = Wire::Frame::Stream::TYPES.fetch(0)
      receiver = receiver_for(frame.stream_id, frame_type: type, now:) or return
      length = frame.data.bytesize
      grown = receiver.admit(frame.offset + length, fin: frame.fin, frame_type: type)
      @window.receive(@window.received + grown, frame_type: type)
      if receiver.abandoned?
        @window.consume(receiver.discard)
        return retire(frame.stream_id)
      end
      gaps = @gaps - receiver.gaps + receiver.gaps_with(frame.offset, length)
      if gaps > @max_gaps
        raise Violation.new("data received in more than #{@max_gaps} pieces", code: ErrorCode::INTERNAL_ERROR, frame_type: type)
      end
      @gaps = gaps
      readable = receiver.readable?
      receiver.insert(frame.offset, frame.data)
      @events << Event::StreamReadable.new(stream_id: frame.stream_id) if !readable && receiver.readable?
    end

    # Up to `max_bytes` of `stream_id`, as Receiver#read gives them,
    # consumed in the connection's window as in the stream's.
    def read(stream_id, max_bytes)
      receiver = @receivers[stream_id]
      return nil if receiver.nil? && over?(stream_id) && receives?(stream_id)
      receiver or raise Error::StreamError, "stream #{stream_id} has nothing to read"
      data = receiver.read(max_bytes)
      @window.consume(data.bytesize) if data
      retire(stream_id)
      data
    end

    # The streams a read would give something on.
    def readable
      @receivers.filter_map { |stream_id, receiver| stream_id if receiver.readable? }
    end

    # The next MAX_DATA, MAX_STREAMS or MAX_STREAM_DATA frame due and its
    # duty, in no more than `room` bytes; nil when none is. `rtt` is the smoothed RTT,
    # nil before the first sample. A stream whose final size is known needs
    # no more credit.
    def next_credit(room, now:, rtt:)
      if @window.update_due?
        return nil if room < 1 + MAX_VARINT_SIZE
        maximum = @window.advance(now:, rtt:)
        return [Wire::Frame::MaxData.new(maximum:), Recovery::Duty::MaxData.new(maximum:)]
      end
      DIRECTIONS.each do |direction|
        next unless max_streams_due?(direction)
        return nil if room < 1 + MAX_VARINT_SIZE
        maximum = @local_max_streams[direction] = streams_allowed(direction)
        @max_streams_resend[direction] = false
        bidirectional = direction == :bidi
        return [Wire::Frame::MaxStreams.new(bidirectional:, maximum:), Recovery::Duty::MaxStreams.new(bidirectional:, maximum:)]
      end
      @receivers.each do |stream_id, receiver|
        window = receiver.window
        next unless window.update_due? && receiver.final_size.nil? && !receiver.abandoned?
        return nil if room < 1 + Wire::Varint.size(stream_id) + MAX_VARINT_SIZE
        size = window.size
        maximum = window.advance(now:, rtt:)
        @window.grow_to((window.size * CONNECTION_WINDOW_FACTOR).ceil, now:) if window.size > size
        return [Wire::Frame::MaxStreamData.new(stream_id:, maximum:), Recovery::Duty::MaxStreamData.new(stream_id:, maximum:)]
      end
      nil
    end

    def max_data_lost(duty) = @window.lost(duty.maximum)

    def max_stream_data_lost(duty) = @receivers[duty.stream_id]&.window&.lost(duty.maximum)

    # A lost MAX_STREAMS goes again while it is the latest.
    def max_streams_lost(duty)
      direction = duty.bidirectional ? :bidi : :uni #: :bidi | :uni
      @max_streams_resend[direction] = true if duty.maximum == @local_max_streams.fetch(direction)
    end

    # How many streams of `direction` the peer may open by now: as many
    # as are over, and as many again as the limit first given, short of
    # 2^60.
    private def streams_allowed(direction)
      initial = direction == :bidi ? @config.initial_max_streams_bidi : @config.initial_max_streams_uni
      [@ended.fetch(direction) + initial, Wire::Frame::MAX_STREAM_COUNT].min
    end

    private def max_streams_due?(direction)
      return true if @max_streams_resend.fetch(direction)
      room = streams_allowed(direction) - @local_max_streams.fetch(direction)
      return false unless room.positive?
      initial = direction == :bidi ? @config.initial_max_streams_bidi : @config.initial_max_streams_uni
      room >= [initial / STREAM_CREDIT_SHARE, 1].max
    end

    # `stream_id` is let go once both its parts are over; one of the
    # peer's makes room for another.
    private def retire(stream_id)
      receiver = @receivers[stream_id]
      sender = @senders[stream_id]
      return if receiver && !receiver.finished?
      return if sender && !(sender.all_acked? || sender.reset_acked?)
      @receivers.delete(stream_id)
      @senders.delete(stream_id)
      @scheduler.forget(stream_id)
      @wanting.delete(stream_id)
      @flow_blocked.delete(stream_id)
      @ended[stream_id & UNIDIRECTIONAL == 0 ? :bidi : :uni] += 1 unless local?(stream_id)
    end

    # Whether `stream_id` has been opened, and so, when it is not held,
    # is over.
    private def over?(stream_id) = stream_id >> 2 < @opened.fetch(stream_id & 0x3)

    # Whether `stream_id` has a receiving part on this end, or a sending
    # part.
    private def receives?(stream_id) = !(local?(stream_id) && stream_id & UNIDIRECTIONAL != 0)

    private def sends?(stream_id) = !(!local?(stream_id) && stream_id & UNIDIRECTIONAL != 0)

    # The connection's credit cut a write short.
    private def data_blocked(now)
      unless @connection_blocked
        @connection_blocked = true
        @tracer&.connection_data_blocked_updated(old: :unblocked, new: :blocked, reason: :connection_flow_control, now:)
      end
      return if @data_blocked_at == @peer_max_data
      @data_blocked_at = @peer_max_data
      @data_blocked_due = true
      @blocked_sent += 1
    end

    # The stream's credit cut a write to `stream_id` short.
    private def stream_blocked(stream_id, now)
      sender = @senders.fetch(stream_id)
      @blocked_sent += 1 if sender.blocked!
      return if @flow_blocked.include?(stream_id)
      @flow_blocked << stream_id
      @tracer&.stream_data_blocked_updated(stream_id:, old: :unblocked, new: :blocked, reason: :stream_flow_control, now:)
    end

    # No stream of `direction` opens past the peer's `limit`: nil, and
    # STREAMS_BLOCKED with it, once for each value of the limit.
    private def streams_blocked(direction, limit)
      return nil if @streams_blocked_at.fetch(direction) == limit
      @streams_blocked_at[direction] = limit
      @streams_blocked_due[direction] = true
      @blocked_sent += 1
      nil
    end

    private def fits?(frame, room) = Wire::Frame.encode([frame], ack_delay_exponent: 0).bytesize <= room

    # The sending part of `stream_id` for a frame of `frame_type`, opening
    # the peer's streams up to it; nil when the stream is over, and a
    # Violation when it has no sending part or cannot be open.
    private def sender_part(stream_id, frame_type:, now:)
      if !local?(stream_id) && stream_id & UNIDIRECTIONAL != 0
        raise Violation.new("stream #{stream_id} only receives", code: ErrorCode::STREAM_STATE_ERROR, frame_type:)
      end
      open_peer_streams(stream_id, frame_type:, now:) unless local?(stream_id)
      check_opened(stream_id, frame_type:)
      @senders[stream_id]
    end

    # The sending part of `stream_id` for the application to write to.
    private def sender_for(stream_id)
      sender = @senders[stream_id] or raise Error::StreamError, "stream #{stream_id} has nothing to write to"
      raise Error::StreamError, "stream #{stream_id} has ended" if sender.fin? || sender.reset?
      sender
    end

    # A stream's sending part is reset: the data it held leaves the send
    # buffer, and what it never sent the connection's count.
    private def abandon_sending(sender, error_code)
      released, unsent = sender.reset!(error_code)
      @buffered -= released
      @written -= unsent
      writable_again
    end

    # What the stream's credit, the connection's and the send buffer all
    # leave room for.
    private def room_for(sender) = [sender.credit, @peer_max_data - @written, @config.max_send_buffer - @buffered].min

    # The sending part of the stream whose turn it is, those with nothing
    # to send let go idle on the way; nil when none has something.
    private def current_sender
      while (stream_id = @scheduler.current)
        sender = @senders[stream_id]
        return sender if sender&.pending?
        @scheduler.idle(stream_id)
      end
      nil
    end

    # The streams written less than asked that can take some now hear so;
    # one that has ended since is let go.
    private def writable_again
      @wanting.reject! do |stream_id|
        sender = @senders[stream_id]
        next true if sender.nil? || sender.fin? || sender.reset?
        next false unless room_for(sender).positive?
        @events << Event::StreamWritable.new(stream_id:)
        true
      end
    end

    # Whether `stream_id` was opened by this end.
    def local?(stream_id) = (stream_id & SERVER_INITIATED == SERVER_INITIATED) == (@role == :server)

    # The receiving part of `stream_id` for a frame of `frame_type`, opening
    # the peer's streams up to it; nil when the stream is over, and a
    # Violation when it has no receiving part or cannot be open.
    private def receiver_for(stream_id, frame_type:, now:)
      if local?(stream_id) && stream_id & UNIDIRECTIONAL != 0
        raise Violation.new("stream #{stream_id} only sends", code: ErrorCode::STREAM_STATE_ERROR, frame_type:)
      end
      open_peer_streams(stream_id, frame_type:, now:) unless local?(stream_id)
      check_opened(stream_id, frame_type:)
      @receivers[stream_id]
    end

    # A stream of this end must have been opened.
    private def check_opened(stream_id, frame_type:)
      return unless local?(stream_id) && stream_id >> 2 >= @opened.fetch(stream_id & 0x3)
      raise Violation.new("stream #{stream_id} is not open", code: ErrorCode::STREAM_STATE_ERROR, frame_type:)
    end

    # The peer's streams of the type of `stream_id`, up to it, open, within
    # the limit given (RFC 9000 "Controlling Concurrency").
    private def open_peer_streams(stream_id, frame_type:, now:)
      type = stream_id & 0x3
      index = stream_id >> 2
      return if index < @opened.fetch(type)
      limit = @local_max_streams.fetch(type & UNIDIRECTIONAL == 0 ? :bidi : :uni)
      if index >= limit
        raise Violation.new("stream #{stream_id} past the limit of #{limit}", code: ErrorCode::STREAM_LIMIT_ERROR, frame_type:)
      end
      (@opened.fetch(type)..index).each { |each_index| open_peer_stream(each_index << 2 | type, now) }
      @opened[type] = index + 1
    end

    private def open_peer_stream(stream_id, now)
      unidirectional = stream_id & UNIDIRECTIONAL != 0
      size = unidirectional ? @config.initial_max_stream_data_uni : @config.initial_max_stream_data_bidi_remote
      @receivers[stream_id] = Receiver.new(window: ReceiveWindow.new(size:, max: @config.max_stream_receive_window, now:))
      return if unidirectional
      @senders[stream_id] = Sender.new(stream_id:, limit: @peer_parameters&.initial_max_stream_data_bidi_local || 0)
    end
  end
end

require_relative "streams/receive_window"
require_relative "streams/receiver"
require_relative "streams/sender"
