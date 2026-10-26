# frozen_string_literal: true

require_relative "action"
require_relative "error"
require_relative "frame"
require_relative "output"
require_relative "priority"
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
      raise ArgumentError, "a field section needs a limit, not #{settings.max_field_section_size.inspect}" if settings.max_field_section_size.nil?
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
    end

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

    # Gives what this layer asks of the transport, Action values, in the
    # order asked.
    def each_action
      yield @actions.shift until @actions.empty?
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
