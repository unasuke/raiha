# frozen_string_literal: true

require_relative "quic"
require_relative "http3"

module Raiha::Next
  # Joins one QUIC connection and the HTTP/3 connection over it, neither of
  # which knows the other: what QUIC tells of its streams goes to HTTP/3,
  # and what HTTP/3 writes and asks of the transport goes to QUIC. It
  # decides nothing of its own beyond opening HTTP/3's three streams once
  # QUIC has connected, and which streams to read.
  #
  # The application gives it each event of the QUIC connection with
  # `receive`, then calls `flush`; HTTP/3's events are then the HTTP/3
  # connection's to take. The streams are read at `flush`, after the
  # events: a stream the peer reset reads as ended, and HTTP/3 has heard of
  # the reset by then, so the end is not taken for its FIN.
  class HTTP3Binding
    # The events of the QUIC connection that are HTTP/3's alone.
    HTTP3_EVENTS = [
      QUIC::Event::StreamReadable, QUIC::Event::StreamWritable, QUIC::Event::StreamReset, QUIC::Event::StopSending,
      QUIC::Event::DatagramReceived
    ].freeze
    # The most bytes one read of a stream asks for.
    READ_SIZE = 64 * 1024

    def initialize(connection, http3)
      @connection = connection
      @http3 = http3
      @paused = {} #: Hash[Integer, true]
      @closed = false
    end

    # Takes `event` of the QUIC connection: whether it was HTTP/3's alone.
    # Event::Connected opens HTTP/3's streams, and Event::Closed stops
    # `flush`; both are for the application too.
    def receive(event, now:)
      case event
      when QUIC::Event::Connected then start(now)
      when QUIC::Event::Closed then @closed = true
      when QUIC::Event::StreamWritable then @http3.stream_writable(event.stream_id)
      when QUIC::Event::StreamReset then @http3.stream_reset(event.stream_id, error_code: event.error_code)
      when QUIC::Event::StopSending then @http3.stream_stopped(event.stream_id, error_code: event.error_code)
      when QUIC::Event::DatagramReceived then @http3.datagram_received(event.data)
      end
      HTTP3_EVENTS.any? { |type| event.is_a?(type) }
    end

    # Reads the streams with something to read into HTTP/3, all but those
    # paused, and gives QUIC what HTTP/3 asks of it, writes to its streams
    # and sends as DATAGRAMs, in that order. Nothing once QUIC has closed.
    def flush(now:)
      return if @closed
      @connection.readable_streams.each { |stream_id| read(stream_id) unless @paused.key?(stream_id) }
      @http3.each_action { |action| perform(action, now) }
      @http3.each_send { |stream_id, data, fin| @connection.stream_write(stream_id, data, fin:) }
      @http3.each_datagram_send { |data, urgency| @connection.datagram_send(data, urgency:) }
    end

    # Leaves `stream_id` unread until `resume`, so that QUIC's flow control
    # holds the peer back.
    def pause(stream_id)
      @paused[stream_id] = true
    end

    # Reads `stream_id` again from the next `flush`.
    def resume(stream_id)
      @paused.delete(stream_id)
    end

    # The control and QPACK streams, three of this end's going one way,
    # which RFC 9114 "Unidirectional Streams" has the peer allow; without
    # them the connection closes with H3_GENERAL_PROTOCOL_ERROR.
    private def start(now)
      @http3.datagram_max_size = @connection.datagram_max_size
      control, encoder, decoder = Array.new(3) { @connection.open_stream(direction: :uni) }
      if control && encoder && decoder
        @http3.start(control:, encoder:, decoder:)
      else
        @connection.close(error_code: HTTP3::ErrorCode::GENERAL_PROTOCOL_ERROR, reason: "fewer than three streams going one way", now:)
      end
    end

    # What `stream_id` has, read at once, and its end if it has ended.
    private def read(stream_id)
      data = "".b
      while (chunk = @connection.stream_read(stream_id, READ_SIZE)) && !chunk.empty?
        data << chunk
      end
      @http3.stream_data(stream_id, data, fin: chunk.nil?) unless data.empty? && chunk
    end

    private def perform(action, now)
      case action
      when HTTP3::Action::Reset then @connection.stream_reset(action.stream_id, error_code: action.error_code)
      when HTTP3::Action::StopSending then @connection.stream_stop_sending(action.stream_id, error_code: action.error_code)
      when HTTP3::Action::Priority then @connection.stream_priority(action.stream_id, urgency: action.urgency, incremental: action.incremental)
      when HTTP3::Action::Close then @connection.close(error_code: action.error_code, reason: action.reason, now:)
      end
    end
  end
end
