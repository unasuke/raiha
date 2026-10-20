# frozen_string_literal: true

require "json"

module Raiha::Next::QUIC
  # qlog (draft-ietf-quic-qlog-main-schema-13 and quic-events-12).
  module Qlog
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
    # length. Events qlog has no name for go under "raiha:": a spurious loss,
    # and the TLS layer's traces as "raiha:tls_" and the name of the trace.
    class Tracer
      include Raiha::Next::QUIC::Tracer

      RECORD_SEPARATOR = "\x1e"
      PACKET_TYPES = { initial: "initial", zero_rtt: "0RTT", handshake: "handshake", one_rtt: "1RTT" }.freeze
      SPACE_PACKET_TYPES = { initial: "initial", handshake: "handshake", application_data: "1RTT" }.freeze
      # The metrics and parameters that are times, in seconds here and
      # milliseconds in qlog.
      TIMES = %i[latest_rtt smoothed_rtt min_rtt rtt_variance max_idle_timeout max_ack_delay timer_granularity initial_rtt].freeze

      # `vantage_point` is :client or :server.
      def initialize(io, vantage_point:, title: nil)
        @io = io
        @now = 0.0
        header = {
          file_schema: "urn:ietf:params:qlog:file:sequential", serialization_format: "application/qlog+json-seq",
          qlog_version: "0.3", qlog_format: "JSON-SEQ", title:,
          trace: {
            vantage_point: { type: vantage_point.to_s },
            common_fields: { time_format: "relative_to_epoch", reference_time: { clock_type: "monotonic", epoch: "unknown" } },
            event_schemas: ["urn:ietf:params:qlog:events:quic"]
          }
        }.compact #: Hash[Symbol, json]
        write(header)
      end

      def trace_frames? = true

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

      def parameters_set(owner:, parameters:, now:)
        event(now, "quic:parameters_set", { owner: owner.to_s, **values(parameters.to_h.compact) })
      end

      # A key update changes the 1-RTT keys of both directions; no key goes
      # in the trace.
      def key_updated(level:, now:)
        %w[client_1rtt_secret server_1rtt_secret].each { |key_type| event(now, "quic:key_updated", { key_type: }) }
      end

      # A trace of the TLS layer: a Data, whose name and fields it takes.
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
      # its length.
      private def frame(frame)
        case frame
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

      private def write(record) = @io.write(RECORD_SEPARATOR, JSON.generate(record), "\n")

      private def hex(bytes) = bytes.unpack1("H*")
    end
  end
end
