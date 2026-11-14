# frozen_string_literal: true

require "json"

module Raiha::QUIC
  # qlog (draft-ietf-quic-qlog-main-schema-13 and quic-events-12).
  module Qlog
    # The bytes the traces given it may write together. What they write is
    # spent and never comes back: once it is gone, they all stop, and a
    # trace begun after writes nothing. A Ractor does not share it, so
    # each worker has its own.
    class Budget
      attr_reader :max_bytes, :spent

      def initialize(max_bytes:)
        raise ArgumentError, "max_bytes is a positive Integer, not #{max_bytes.inspect}" unless max_bytes.is_a?(Integer) && max_bytes.positive?
        @max_bytes = max_bytes
        @spent = 0
      end

      def left = @max_bytes - @spent

      # A trace wrote `bytes`, which it has made sure are left.
      def spend(bytes)
        @spent += bytes
      end
    end

    # A Tracer that writes the qlog of one connection as a JSON Text
    # Sequence (RFC 7464) to `io`, a record as each event happens, so that
    # the trace of a connection that dies keeps what came before it. The
    # header also has the qlog_version and qlog_format of the earlier
    # drafts, which qvis looks for.
    #
    # Times are milliseconds of the monotonic clock the connection is given;
    # a trace of the TLS layer, which comes with no time, has the time of
    # the event before it, which the same input caused.
    # Connection IDs and other bytes are hex; the bytes of data, only their
    # length, but the data of a path challenge and response. Events qlog has no name for go under "raiha:": a spurious loss,
    # and the TLS layer's traces as "raiha:tls_" and the name of the trace.
    # A layer above QUIC writes its own events with `record`, at the time of
    # the event before them, and names its schema in `event_schemas`.
    #
    # The trace of one connection writes no more than `max_bytes`, however
    # long the peer keeps it busy, and the traces given one `budget` no
    # more than it together, however many connections a peer opens: the
    # record that would go past either, less the room for one more, goes
    # instead as "raiha:qlog_stopped" with the limit, and nothing comes
    # after it; a trace whose header does not fit writes nothing. Keeping
    # the files apart, and taking the old ones away, is up to whoever
    # gives each trace its `io`.
    class Tracer
      include Raiha::QUIC::Tracer

      RECORD_SEPARATOR = "\x1e"
      PACKET_TYPES = { initial: "initial", zero_rtt: "0RTT", handshake: "handshake", one_rtt: "1RTT" }.freeze
      SPACE_PACKET_TYPES = { initial: "initial", handshake: "handshake", application_data: "1RTT" }.freeze
      # The metrics and parameters that are times, in seconds here and
      # milliseconds in qlog.
      TIMES = %i[latest_rtt smoothed_rtt min_rtt rtt_variance max_idle_timeout max_ack_delay timer_granularity initial_rtt].freeze
      DEFAULT_MAX_BYTES = 64 * 1024 * 1024
      # The room kept for the record that says the trace stopped.
      STOP_ROOM = 256

      # `vantage_point` is :client or :server.
      def initialize(io, vantage_point:, title: nil, max_bytes: DEFAULT_MAX_BYTES, budget: nil, event_schemas: [])
        raise ArgumentError, "max_bytes is a positive Integer, not #{max_bytes.inspect}" unless max_bytes.is_a?(Integer) && max_bytes.positive?
        @io = io
        @max_bytes = max_bytes
        @budget = budget
        @written = 0
        @stopped = false
        @now = 0.0
        header = {
          file_schema: "urn:ietf:params:qlog:file:sequential", serialization_format: "application/qlog+json-seq",
          qlog_version: "0.3", qlog_format: "JSON-SEQ", title:,
          trace: {
            vantage_point: { type: vantage_point.to_s },
            common_fields: { time_format: "relative_to_epoch", reference_time: { clock_type: "monotonic", epoch: "unknown" } },
            event_schemas: ["urn:ietf:params:qlog:events:quic", *event_schemas]
          }
        }.compact #: Hash[Symbol, json]
        write(header)
      end

      # Whether the connection lists the frames of each packet: not once the
      # trace has stopped.
      def trace_frames? = !@stopped

      def packet_sent(header:, frames:, raw_length:, now:) = packet("quic:packet_sent", header, frames, raw_length, now)

      def packet_received(header:, frames:, raw_length:, now:) = packet("quic:packet_received", header, frames, raw_length, now)

      def packet_dropped(reason:, raw_length:, now:) = event(now, "quic:packet_dropped", { raw: { length: raw_length }, trigger: reason.to_s })

      def packet_lost(packet_number:, space:, trigger:, mtu_probe:, now:)
        header = { packet_type: SPACE_PACKET_TYPES.fetch(space), packet_number: } #: Hash[Symbol, json]
        event(now, "quic:packet_lost", { header:, trigger: trigger.to_s, is_mtu_probe_packet: mtu_probe })
      end

      def metrics_updated(now:, **metrics) = event(now, "quic:recovery_metrics_updated", values(metrics))

      def timer_updated(timer_type:, event_type:, space:, delta:, now:)
        data = { timer_type: timer_type.to_s, packet_number_space: space&.to_s, event_type: event_type.to_s, delta: delta && delta * 1000 }
        event(now, "quic:timer_updated", data.compact)
      end

      def ecn_state_updated(old:, new:, now:) = event(now, "quic:ecn_state_updated", { old: old.to_s, new: new.to_s })

      def recovery_parameters_set(now:, **parameters) = event(now, "quic:recovery_parameters_set", values(parameters))

      def spurious_loss(packet_number:, space:, now:)
        event(now, "raiha:spurious_loss", { packet_number_space: space.to_s, packet_number: })
      end

      def congestion_state_updated(old:, new:, now:) = event(now, "quic:congestion_state_updated", { old: old.to_s, new: new.to_s })

      def connection_data_blocked_updated(old:, new:, reason:, now:)
        event(now, "quic:connection_data_blocked_updated", { old: old.to_s, new: new.to_s, reason: reason.to_s })
      end

      def stream_data_blocked_updated(stream_id:, old:, new:, reason:, now:)
        event(now, "quic:stream_data_blocked_updated", { old: old.to_s, new: new.to_s, stream_id:, reason: reason.to_s })
      end

      def mtu_updated(old:, new:, done:, now:) = event(now, "quic:mtu_updated", { old:, new:, done: })

      def connection_id_updated(owner:, old:, new:, now:)
        event(now, "quic:connection_id_updated", { owner: owner.to_s, old: hex(old), new: hex(new) })
      end

      def migration_state_updated(state:, local:, remote:, now:)
        data = { new: state.to_s, path_local: endpoint(local), path_remote: endpoint(remote) } #: Hash[Symbol, json]
        event(now, "quic:migration_state_updated", data.compact)
      end

      def parameters_set(owner:, parameters:, now:)
        event(now, "quic:parameters_set", { owner: owner.to_s, **values(parameters.to_h.compact) })
      end

      # A key update changes the 1-RTT keys of both directions; no key goes
      # in the trace.
      def key_updated(level:, now:)
        %w[client_1rtt_secret server_1rtt_secret].each { |key_type| event(now, "quic:key_updated", { key_type: }) }
      end

      # A trace of the TLS layer: a Data, whose name and fields it takes.
      # An event of a layer above QUIC, `name` with `data`, already as qlog
      # has it.
      def record(name, data) = write({ time: @now * 1000, name:, data: })

      def tls_trace(value)
        name = value.class.name.to_s.split("::").last.to_s.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase
        write({ time: @now * 1000, name: "raiha:tls_#{name}", data: values(value.to_h) })
      end

      private def packet(name, header, frames, raw_length, now)
        fields = {
          packet_type: PACKET_TYPES.fetch(header.packet_type), packet_number: header.packet_number,
          version: header.version&.then { format("%08x", _1) }, dcid: hex(header.dcid), scid: header.scid&.then { hex(_1) },
          key_phase: header.key_phase
        } #: Hash[Symbol, json]
        data = { header: fields.compact, frames: frames&.map { |frame| frame(frame) }, raw: { length: raw_length } } #: Hash[Symbol, json]
        event(now, name, data.compact)
      end

      # A frame as qlog has it: its type, and its fields, with data as
      # its length but a path challenge's and response's, in hex.
      private def frame(frame)
        case frame
        when Wire::Frame::PathChallenge then { frame_type: "path_challenge", data: hex(frame.data) }
        when Wire::Frame::PathResponse then { frame_type: "path_response", data: hex(frame.data) }
        when Wire::Frame::Ack
          ranges = frame.ranges.reverse.map { |range| [range.begin, range.end] } #: Array[json]
          { frame_type: "ack", ack_delay: frame.delay * 1000, acked_ranges: ranges }
        when Wire::Frame::ConnectionClose
          { frame_type: "connection_close", error_space: frame.application ? "application" : "transport", error_code: frame.code,
            trigger_frame_type: frame.frame_type, reason: frame.reason.dup.force_encoding(Encoding::UTF_8).scrub }.compact
        else
          name = frame.class.name.to_s.split("::").last.to_s.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase
          { frame_type: name, **values(frame.to_h) }
        end
      end

      # `fields` as qlog values: times in milliseconds, bytes as hex, data
      # as its length, Symbols as Strings.
      private def values(fields)
        fields.to_h do |name, value|
          case value
          when String then name == :data || name == :token ? [:raw, { length: value.bytesize }] : [name, hex(value)]
          when Float, Integer then [name, TIMES.include?(name) ? value * 1000 : value]
          when Symbol then [name, value.to_s]
          when true, false, nil then [name, value]
          when Data then [name, values(value.to_h)]
          when Array then [name, value.map { |each| each.is_a?(String) ? hex(each) : each.to_s }]
          else [name, value.to_s]
          end
        end
      end

      private def event(now, name, data)
        @now = now
        write({ time: now * 1000, name:, data: })
      end

      private def write(record)
        return if @stopped
        json = JSON.generate(record)
        unless room_for?(record_size(json) + STOP_ROOM)
          @stopped = true
          return if @written.zero?
          json = JSON.generate({ time: @now * 1000, name: "raiha:qlog_stopped", data: stop_reason(record_size(json) + STOP_ROOM) })
          return unless room_for?(record_size(json))
        end
        @written += record_size(json)
        @budget&.spend(record_size(json))
        @io.write(RECORD_SEPARATOR, json, "\n")
      end

      # Which limit `bytes` more would go past, and how large it is.
      private def stop_reason(bytes)
        return { reason: "max_bytes", max_bytes: @max_bytes } if @budget.nil? || @written + bytes > @max_bytes
        { reason: "budget", max_bytes: @budget.max_bytes } # steep:ignore
      end

      # Whether this trace and its budget both have `bytes` left.
      private def room_for?(bytes) = @written + bytes <= @max_bytes && (@budget.nil? || bytes <= @budget.left) # steep:ignore

      # The bytes `json` takes in the sequence, with the separator before it
      # and the line feed after.
      private def record_size(json) = RECORD_SEPARATOR.bytesize + json.bytesize + 1

      private def hex(bytes) = bytes.unpack1("H*")

      # An address as qlog's PathEndpointInfo has it, by its family; nil
      # for none.
      private def endpoint(address)
        host, port = address || (return nil)
        host.include?(":") ? { ip_v6: host, port_v6: port } : { ip_v4: host, port_v4: port }
      end
    end
  end
end
