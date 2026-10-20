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
  # most MAX_RECV_GAPS, past which the connection closes with
  # INTERNAL_ERROR rather than dropping data an ACK has already covered.
  #
  # A stream that had nothing to read and has now tells the application
  # with Event::StreamReadable, once, as the application reads it until it
  # gives "" or nil.
  class Streams
    # The holes the data received may have, all the streams together.
    MAX_RECV_GAPS = 1000
    # The low bits of a stream ID: who opened it, and which way it goes.
    SERVER_INITIATED = 0x01
    UNIDIRECTIONAL = 0x02

    # The connection's receive window.
    attr_reader :window

    # Events go to `events`.
    def initialize(role:, config:, events:, now:)
      @role = role
      @config = config
      @events = events
      @window = ReceiveWindow.new(size: config.initial_max_data, max: config.max_receive_window, now:)
      @receivers = {} #: Hash[Integer, Receiver]
      @senders = {} #: Hash[Integer, Sender]
      # How many streams of each type (the low two bits of an ID) are open.
      @opened = [0, 0, 0, 0]
      @gaps = 0
      @peer_parameters = nil #: TransportParameters?
    end

    # The peer's transport parameters, which set the limits of what this
    # end sends.
    def peer_parameters=(parameters)
      @peer_parameters = parameters
    end

    # Takes a STREAM frame: its data is kept, once every check passes.
    def receive_stream(frame, now:)
      type = Wire::Frame::Stream::TYPES.fetch(0)
      receiver = receiver_for(frame.stream_id, frame_type: type, now:) or return
      length = frame.data.bytesize
      grown = receiver.admit(frame.offset + length, fin: frame.fin, frame_type: type)
      @window.receive(@window.received + grown, frame_type: type)
      gaps = @gaps - receiver.gaps + receiver.gaps_with(frame.offset, length)
      if gaps > MAX_RECV_GAPS
        raise Violation.new("data received in more than #{MAX_RECV_GAPS} pieces", code: ErrorCode::INTERNAL_ERROR, frame_type: type)
      end
      @gaps = gaps
      readable = receiver.readable?
      receiver.insert(frame.offset, frame.data)
      @events << Event::StreamReadable.new(stream_id: frame.stream_id) if !readable && receiver.readable?
    end

    # Up to `max_bytes` of `stream_id`, as Receiver#read gives them,
    # consumed in the connection's window as in the stream's.
    def read(stream_id, max_bytes)
      receiver = @receivers[stream_id] or raise Error::StreamError, "stream #{stream_id} has nothing to read"
      data = receiver.read(max_bytes)
      @window.consume(data.bytesize) if data
      data
    end

    # The streams a read would give something on.
    def readable
      @receivers.filter_map { |stream_id, receiver| stream_id if receiver.readable? }
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
      limit = type & UNIDIRECTIONAL == 0 ? @config.initial_max_streams_bidi : @config.initial_max_streams_uni
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
