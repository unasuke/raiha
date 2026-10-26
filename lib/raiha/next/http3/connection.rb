# frozen_string_literal: true

require_relative "action"
require_relative "error"
require_relative "event"
require_relative "frame"
require_relative "frame_reader"
require_relative "message"
require_relative "output"
require_relative "priority"
require_relative "qpack"
require_relative "receiving"
require_relative "settings"
require_relative "varint"

module Raiha::Next::HTTP3
  # One HTTP/3 connection (RFC 9114), sans-IO and over no transport in
  # particular: it takes the bytes of streams and gives back what to write
  # to them, what else to ask of the transport (Action), and what happened
  # (Event). The stream IDs are the transport's: this layer is given the
  # streams it is to use, never opens one.
  #
  # The bytes for a stream wait here until the transport takes them:
  # `each_send` gives them, a stream at a time and the most urgent first,
  # so that what is urgent finds room in the transport's send buffer, and
  # a stream the transport takes less than given from waits until
  # `stream_writable`.
  class Connection
    # The types of unidirectional streams (RFC 9114 "Unidirectional
    # Streams", RFC 9204 "Encoder and Decoder Streams").
    CONTROL_STREAM = 0x00
    PUSH_STREAM = 0x01
    ENCODER_STREAM = 0x02
    DECODER_STREAM = 0x03
    DEFAULT_MAX_SEND_BUFFER = 64 * 1024
    # The control and QPACK streams: little goes on them, and nothing is to
    # wait behind it.
    CRITICAL = Priority.new(urgency: 0, incremental: true)
    TRANSPORT_ORDERINGS = %i[per_stream global].freeze
    # The types of the streams each end opens one of, and must never close.
    CRITICAL_STREAMS = { CONTROL_STREAM => "control", ENCODER_STREAM => "QPACK encoder", DECODER_STREAM => "QPACK decoder" }.freeze
    # The longest a frame on the control stream is held, its payload; a
    # longer one is H3_EXCESSIVE_LOAD.
    MAX_CONTROL_FRAME = 16 * 1024
    # The frames that never go on a control stream (RFC 9114 "HTTP Framing
    # Layer"), and those only a client sends on one.
    NOT_ON_CONTROL = [Frame::DATA, Frame::HEADERS, Frame::PUSH_PROMISE, *Frame::HTTP2_TYPES].freeze
    FROM_CLIENTS = [Frame::MAX_PUSH_ID, Frame::PRIORITY_UPDATE, Frame::PRIORITY_UPDATE_PUSH].freeze
    # The most frames, and pieces of DATA, a request stream holds while its
    # field section waits on QPACK; the bytes of DATA are held to the
    # longest a field section may be. The transport's flow control does not
    # bound them, as what is read here gives the peer credit.
    MAX_WAITING = 1024
    # The frames this layer knows that never go on a request stream (RFC
    # 9114 "HTTP Framing Layer"). PUSH_PROMISE goes on one only from a
    # server.
    NOT_ON_REQUEST = [
      Frame::CANCEL_PUSH, Frame::SETTINGS, Frame::GOAWAY, Frame::MAX_PUSH_ID, Frame::PRIORITY_UPDATE, Frame::PRIORITY_UPDATE_PUSH,
      *Frame::HTTP2_TYPES
    ].freeze

    attr_reader :role, :settings

    # A client's: `settings` are this end's to tell, `transport_ordering`
    # whether the transport orders the bytes of different streams, :global,
    # or not, :per_stream as QUIC does, and `max_send_buffer` the bytes of
    # data a stream holds for the transport at most.
    def self.client(settings: Settings.new, transport_ordering: :per_stream, max_send_buffer: DEFAULT_MAX_SEND_BUFFER)
      new(role: :client, settings:, transport_ordering:, max_send_buffer:)
    end

    # A server's, which takes Extended CONNECT by default (RFC 9220).
    def self.server(settings: Settings.new(enable_connect_protocol: true), transport_ordering: :per_stream, max_send_buffer: DEFAULT_MAX_SEND_BUFFER)
      new(role: :server, settings:, transport_ordering:, max_send_buffer:)
    end

    def initialize(role:, settings:, transport_ordering:, max_send_buffer:)
      limit = settings.max_field_section_size or raise ArgumentError, "a field section needs a limit, not nil"
      raise ArgumentError, "transport_ordering is :per_stream or :global, not #{transport_ordering.inspect}" unless TRANSPORT_ORDERINGS.include?(transport_ordering)
      raise ArgumentError, "max_send_buffer is a positive Integer, not #{max_send_buffer.inspect}" unless max_send_buffer.is_a?(Integer) && max_send_buffer.positive?
      @role = role
      @settings = settings
      @transport_ordering = transport_ordering
      @max_send_buffer = max_send_buffer
      @outputs = {} #: Hash[Integer, Output]
      @priorities = {} #: Hash[Integer, Priority]
      @actions = [] #: Array[Action::t]
      @started = false
      # This end's control and QPACK streams; the peer's going one way, by
      # ID, with their type or the bytes of it so far; and the peer's
      # control and QPACK streams, by type.
      @own_critical = [] #: Array[Integer]
      @own_qpack_streams = nil #: [Integer, Integer]?
      @incoming = {} #: Hash[Integer, Integer | String]
      @critical = {} #: Hash[Integer, Integer]
      @closed = false
      # The frames of the peer's control stream, and the settings they gave.
      @control_reader = FrameReader.new(max_payload: MAX_CONTROL_FRAME)
      @peer_settings = nil #: Settings?
      @events = [] #: Array[Event::t]
      # QPACK: this end's decoder takes the peer's encoder stream and field
      # sections, by this end's settings; its encoder writes field sections
      # and takes the peer's decoder stream.
      @decoder = QPACK::Decoder.new(
        max_table_capacity: settings.qpack_max_table_capacity, max_blocked_streams: settings.qpack_blocked_streams,
        max_field_section_size: limit
      )
      @encoder = QPACK::Encoder.new
      # The request streams being received, and the longest field section a
      # HEADERS frame may carry: one line takes no more on the wire than
      # four times what it counts for (RFC 9204's decoder holds no longer).
      @receiving = {} #: Hash[Integer, Receiving]
      # The lowest ID of the peer's request streams not seen yet, and those
      # below it skipped, which may still come.
      @next_request = 0
      @skipped = {} #: Hash[Integer, true]
      @field_section_limit = limit
      @max_section = QPACK::Decoder::EXPANSION_BOUND * limit
    end

    # The peer's settings; nil until its SETTINGS frame has come.
    attr_reader :peer_settings

    # Whether this layer has closed the connection, after which it takes
    # nothing more.
    def closed? = @closed

    # The transport opened `control`, `encoder` and `decoder`, streams of
    # this end going one way, for the control stream and the QPACK
    # streams: their types go on them, and this end's SETTINGS.
    def start(control:, encoder:, decoder:)
      raise Error::Usage, "the connection has its streams already" if @started
      streams = [control, encoder, decoder]
      streams.each do |stream_id|
        raise ArgumentError, "stream #{stream_id.inspect} is not one of this end going one way" unless local_unidirectional?(stream_id)
      end
      raise ArgumentError, "three streams, not one twice" unless streams.uniq.size == 3
      @started = true
      @own_critical = streams
      @own_qpack_streams = [encoder, decoder]
      output(control) << Varint.encode(CONTROL_STREAM) << Frame.encode(@settings.to_frame)
      output(encoder) << Varint.encode(ENCODER_STREAM)
      output(decoder) << Varint.encode(DECODER_STREAM)
      streams.each { |stream_id| prioritize(stream_id, CRITICAL) }
    end

    # Gives the bytes waiting for each stream, the most urgent stream first:
    # the block writes `data` to `stream_id`, ending it with `fin`, and
    # returns how many bytes it took. What it does not take waits, and so
    # does the stream, until `stream_writable`.
    def each_send(&)
      return if @closed
      take_qpack_instructions
      ready = @outputs.select { |_, output| output.ready? }.keys
      ready.sort_by! { |stream_id| [priority_of(stream_id).urgency, stream_id] }
      ready.each do |stream_id|
        output = @outputs.fetch(stream_id)
        ended = output.drain { |data, fin| yield(stream_id, data, fin) }
        @outputs.delete(stream_id) if ended
      end
    end

    # The transport can take more of `stream_id`.
    def stream_writable(stream_id)
      @outputs[stream_id]&.unblock
    end

    # The transport received `data` on `stream_id`, and the end of the
    # stream with `fin`.
    def stream_data(stream_id, data, fin: false)
      raise ArgumentError, "stream #{stream_id} is this end's and goes one way" if local_unidirectional?(stream_id)
      return if @closed
      if stream_id & 0x2 != 0
        unidirectional_data(stream_id, data, fin)
      else
        bidirectional_data(stream_id, data, fin)
      end
    rescue Violation => violation
      close_with(violation.code, violation.message)
    end

    # The peer reset `stream_id`, with `error_code`.
    def stream_reset(stream_id, error_code:)
      return if @closed
      if stream_id & 0x2 == 0
        @decoder.cancel(stream_id) if @receiving.delete(stream_id)
        @skipped.delete(stream_id)
        return
      end
      type = @incoming.delete(stream_id)
      return unless type.is_a?(Integer) && CRITICAL_STREAMS.key?(type)
      close_with(ErrorCode::CLOSED_CRITICAL_STREAM, "the peer reset its #{CRITICAL_STREAMS.fetch(type)} stream")
    end

    # The peer asked this end to stop sending on `stream_id`, with
    # `error_code`, and the transport reset it.
    def stream_stopped(stream_id, error_code:)
      return if @closed
      return unless @own_critical.include?(stream_id)
      close_with(ErrorCode::CLOSED_CRITICAL_STREAM, "the peer stopped this end's stream #{stream_id}")
    end

    # Gives what this layer asks of the transport, Action values, in the
    # order asked.
    def each_action
      yield @actions.shift until @actions.empty?
    end

    # Gives what happened, Event values, in the order it happened.
    def each_event
      yield @events.shift until @events.empty?
    end

    # Bytes on a stream of the peer going one way: first its type (RFC 9114
    # "Unidirectional Streams"), then what the type says. A stream may end
    # before its type comes.
    private def unidirectional_data(stream_id, data, fin)
      type = @incoming[stream_id]
      unless type.is_a?(Integer)
        bytes = type ? type + data : data
        type, offset = Varint.decode(bytes)
        unless type && offset
          fin ? @incoming.delete(stream_id) : @incoming[stream_id] = bytes
          return
        end
        open_unidirectional(stream_id, type)
        @incoming[stream_id] = type
        data = bytes.byteslice(offset..) #: String
      end
      unless CRITICAL_STREAMS.key?(type)
        @incoming.delete(stream_id) if fin
        return
      end
      case type
      when CONTROL_STREAM then @control_reader.feed(data) { |item| control_item(item) }
      when ENCODER_STREAM
        results = @decoder.receive_encoder_stream(data)
        qpack_failed(results)
        results.each { |result| unblocked(result) } if results.is_a?(Array)
      when DECODER_STREAM then qpack_failed(@encoder.receive_decoder_stream(data))
      end
      raise Violation.new("the peer closed its #{CRITICAL_STREAMS.fetch(type)} stream", code: ErrorCode::CLOSED_CRITICAL_STREAM) if fin
    end

    # What the peer's control stream holds: its SETTINGS first and once,
    # and only the frames a control stream carries (RFC 9114 "Control
    # Streams", "HTTP Framing Layer").
    private def control_item(item)
      case item
      when FrameReader::Started
        type = item.type
        if @peer_settings.nil? && type != Frame::SETTINGS
          raise Violation.new("a frame of type 0x#{type.to_s(16)} before SETTINGS", code: ErrorCode::MISSING_SETTINGS)
        end
        if (type == Frame::SETTINGS && @peer_settings) || NOT_ON_CONTROL.include?(type) || (@role == :client && FROM_CLIENTS.include?(type))
          raise Violation.new("a frame of type 0x#{type.to_s(16)} on the control stream", code: ErrorCode::FRAME_UNEXPECTED)
        end
      when FrameReader::TooLong
        raise Violation.new("a frame of #{item.length} bytes on the control stream", code: ErrorCode::EXCESSIVE_LOAD)
      when Frame::Settings
        settings = Settings.from_frame(item)
        @peer_settings = settings
        @events << Event::Settings.new(settings:)
      end
    end

    # The peer opened `stream_id`, of `type`: one each of the control and
    # QPACK streams, no push stream, as this end allows no push, and a type
    # not known passed over (RFC 9114 "Unidirectional Streams").
    private def open_unidirectional(stream_id, type)
      if CRITICAL_STREAMS.key?(type)
        raise Violation.new("a second #{CRITICAL_STREAMS.fetch(type)} stream", code: ErrorCode::STREAM_CREATION_ERROR) if @critical.key?(type)
        @critical[type] = stream_id
      elsif type == PUSH_STREAM
        raise Violation.new("a push stream from a client", code: ErrorCode::STREAM_CREATION_ERROR) if @role == :server
        raise Violation.new("a push stream, with no push allowed", code: ErrorCode::ID_ERROR)
      else
        @actions << Action::StopSending.new(stream_id:, error_code: ErrorCode::STREAM_CREATION_ERROR)
      end
    end

    # Bytes on a stream going both ways: a server's are requests; a client
    # takes none the server opens (RFC 9114 "Bidirectional Streams").
    private def bidirectional_data(stream_id, data, fin)
      if @role == :client
        raise Violation.new("a stream going both ways from a server", code: ErrorCode::STREAM_CREATION_ERROR) if stream_id & 0x1 != 0
        return
      end
      receiving = @receiving[stream_id] || open_request(stream_id) or return
      receiving.reader.feed(data) { |item| request_item(stream_id, receiving, item) }
      request_ended(stream_id, receiving) if fin && @receiving[stream_id].equal?(receiving)
    end

    # A request stream the peer opened: one past those seen so far, or one
    # below them it skipped, as the IDs of a peer's streams come in order
    # but their bytes need not; nil for one that ended or was stopped, whose
    # late bytes are dropped. How many are skipped is bounded by the
    # transport's limit on the peer's streams.
    private def open_request(stream_id)
      if stream_id >= @next_request
        skipped = @next_request
        while skipped < stream_id
          @skipped[skipped] = true
          skipped += 4
        end
        @next_request = stream_id + 4
      else
        @skipped.delete(stream_id) or return nil
      end
      @receiving[stream_id] = Receiving.new(max_payload: @max_section)
    end

    # What a request stream holds: a field section before anything else,
    # and none of the frames that go elsewhere. While the field section
    # waits on QPACK, what follows it waits too.
    private def request_item(stream_id, receiving, item)
      return unless @receiving[stream_id].equal?(receiving)
      return wait(stream_id, receiving, item) if receiving.blocked?
      case item
      when FrameReader::Started
        type = item.type
        if NOT_ON_REQUEST.include?(type) || type == Frame::PUSH_PROMISE || (type == Frame::DATA && receiving.phase == :headers)
          raise Violation.new("a frame of type 0x#{type.to_s(16)} on a request stream", code: ErrorCode::FRAME_UNEXPECTED)
        end
      when Frame::Headers
        if receiving.phase == :headers
          section_decoded(stream_id, receiving, @decoder.decode(stream_id, item.field_section, limit: @field_section_limit))
        end
      end
    end

    # Holds `item` until the field section of `stream_id` is decoded, no more
    # than MAX_WAITING of them and no more DATA than a field section may be
    # long; past either, the stream stops with H3_EXCESSIVE_LOAD.
    private def wait(stream_id, receiving, item)
      receiving.waiting_bytes += item.data.bytesize if item.is_a?(Frame::Data)
      return stream_error(stream_id, ErrorCode::EXCESSIVE_LOAD) if receiving.waiting.size >= MAX_WAITING || receiving.waiting_bytes > @max_section
      receiving.waiting << item
    end

    # The QPACK decoder's `result` for the field section of `stream_id`.
    private def section_decoded(stream_id, receiving, result)
      case result
      when QPACK::Decoded
        headers = result.fields.map { |field| [field.name, field.value] } #: Array[[String, String]]
        begin
          Message.request(headers, extended_connect: @settings.enable_connect_protocol)
        rescue Message::Malformed
          return stream_error(stream_id, ErrorCode::MESSAGE_ERROR)
        end
        receiving.phase = :body
        @events << Event::Headers.new(stream_id:, headers:, fin: false)
      when QPACK::Blocked
        receiving.phase = :blocked
        @events << Event::Blocked.new(stream_id:)
      when QPACK::Failure
        raise Violation.new(result.reason, code: result.code) unless result.stream_id
        stream_error(stream_id, result.code)
      end
    end

    # A field section that waited on QPACK is decoded: what waited behind
    # it follows.
    private def unblocked(result)
      stream_id = result.stream_id or return
      receiving = @receiving[stream_id] or return
      receiving.phase = :headers
      section_decoded(stream_id, receiving, result)
      return unless @receiving.key?(stream_id)
      until receiving.waiting.empty? || receiving.blocked? || !@receiving.key?(stream_id)
        item = receiving.waiting.shift or break
        request_item(stream_id, receiving, item)
      end
      request_ended(stream_id, receiving) if receiving.fin_waiting && !receiving.blocked? && @receiving.key?(stream_id)
    end

    # The request on `stream_id` ended: within a frame, H3_FRAME_ERROR;
    # before its field section, H3_REQUEST_INCOMPLETE (RFC 9114 "Frame
    # Layout", "HTTP Message Framing"); else its last event, or an empty
    # Event::Data, tells so.
    private def request_ended(stream_id, receiving)
      return receiving.fin_waiting = true if receiving.blocked?
      raise Violation.new("the stream ended within a frame", code: ErrorCode::FRAME_ERROR) if receiving.reader.mid_frame?
      return stream_error(stream_id, ErrorCode::REQUEST_INCOMPLETE) if receiving.phase == :headers
      @receiving.delete(stream_id)
      last = @events.last
      if (last.is_a?(Event::Headers) || last.is_a?(Event::Data)) && last.stream_id == stream_id
        @events[-1] = last.with(fin: true)
      else
        @events << Event::Data.new(stream_id:, data: "", fin: true)
      end
    end

    # Stops `stream_id` both ways with `code` (RFC 9114 "Request
    # Cancellation and Rejection").
    private def stream_error(stream_id, code)
      @receiving.delete(stream_id)
      @decoder.cancel(stream_id)
      @outputs.delete(stream_id)
      @actions << Action::StopSending.new(stream_id:, error_code: code) << Action::Reset.new(stream_id:, error_code: code)
    end

    # QPACK's connection error, if `result` is one.
    private def qpack_failed(result)
      raise Violation.new(result.reason, code: result.code) if result.is_a?(QPACK::Failure)
    end

    # What this end's QPACK encoder and decoder have to write go on their
    # streams, once the transport has given them.
    private def take_qpack_instructions
      encoder, decoder = @own_qpack_streams || return
      { encoder => @encoder.take_instructions, decoder => @decoder.take_instructions }.each do |stream_id, instructions|
        output(stream_id) << instructions unless instructions.empty?
      end
    end

    # Closes the connection with `code` for `reason`: nothing waits to be
    # sent any more, and nothing is taken.
    private def close_with(code, reason)
      @closed = true
      @outputs.clear
      @actions << Action::Close.new(error_code: code, reason:)
    end

    private def output(stream_id) = @outputs[stream_id] ||= Output.new

    private def prioritize(stream_id, priority)
      @priorities[stream_id] = priority
      @actions << Action::Priority.new(stream_id:, urgency: priority.urgency, incremental: priority.incremental)
    end

    private def priority_of(stream_id) = @priorities.fetch(stream_id) { Priority.new }

    # Whether `stream_id` is of this end and goes one way (RFC 9000 "Stream
    # Types and Identifiers").
    private def local_unidirectional?(stream_id)
      stream_id.is_a?(Integer) && stream_id.between?(0, Varint::MAX) && stream_id & 0x3 == (@role == :client ? 0x2 : 0x3)
    end
  end
end
