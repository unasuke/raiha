# frozen_string_literal: true

require_relative "connection"
require_relative "frame"
require_relative "settings"
require_relative "tracer"

module Raiha::Next::HTTP3
  # qlog for HTTP/3 (draft-ietf-quic-qlog-h3-events-12).
  module Qlog
    # The schema of these events, under the draft's number, as the draft
    # asks until it is an RFC.
    EVENT_SCHEMA = "urn:ietf:params:qlog:events:http3-12"

    # A Tracer that writes the events of an HTTP/3 connection to `writer`,
    # which takes them with `record(name, data)` in qlog's form: QUIC's
    # Qlog::Tracer for the same connection, which bounds how much is
    # written. What the peer sent is cut short here: a name or a value of a
    # field to MAX_FIELD_BYTES, a field section to MAX_FIELDS lines, the
    # rest counted, so that one event stays small however large what it
    # tells of. A name or value that is not text goes as hex.
    class Tracer
      include Raiha::Next::HTTP3::Tracer

      MAX_FIELD_BYTES = 256
      MAX_FIELDS = 64
      TEXT = /\A[\x20-\x7e\t]*\z/n
      STREAM_TYPES = {
        Connection::CONTROL_STREAM => "control", Connection::PUSH_STREAM => "push",
        Connection::ENCODER_STREAM => "qpack_encode", Connection::DECODER_STREAM => "qpack_decode"
      }.freeze
      SETTING_NAMES = {
        Settings::QPACK_MAX_TABLE_CAPACITY => "settings_qpack_max_table_capacity",
        Settings::MAX_FIELD_SECTION_SIZE => "settings_max_field_section_size",
        Settings::QPACK_BLOCKED_STREAMS => "settings_qpack_blocked_streams",
        Settings::ENABLE_CONNECT_PROTOCOL => "settings_enable_connect_protocol",
        Settings::H3_DATAGRAM => "settings_h3_datagram"
      }.freeze
      FRAME_TYPES = {
        Frame::DATA => "data", Frame::HEADERS => "headers", Frame::CANCEL_PUSH => "cancel_push", Frame::SETTINGS => "settings",
        Frame::PUSH_PROMISE => "push_promise", Frame::GOAWAY => "goaway", Frame::MAX_PUSH_ID => "max_push_id",
        Frame::PRIORITY_UPDATE => "priority_update", Frame::PRIORITY_UPDATE_PUSH => "priority_update"
      }.freeze

      def initialize(writer)
        @writer = writer
      end

      def parameters_set(initiator:, settings:)
        data = {
          initiator: initiator.to_s, max_field_section_size: settings.max_field_section_size, max_table_capacity: settings.qpack_max_table_capacity,
          blocked_streams_count: settings.qpack_blocked_streams, extended_connect: settings.enable_connect_protocol ? 1 : 0,
          h3_datagram: settings.h3_datagram ? 1 : 0
        }.compact #: Hash[Symbol, json]
        @writer.record("http3:parameters_set", data)
      end

      def stream_type_set(initiator:, stream_id:, type:)
        data = { initiator: initiator.to_s, stream_id: } #: Hash[Symbol, json]
        if type == :request
          data[:stream_type] = "request"
        elsif (name = STREAM_TYPES[type])
          data[:stream_type] = name
        else
          data[:stream_type] = reserved?(type) ? "reserved" : "unknown"
          data[:stream_type_bytes] = type
        end
        @writer.record("http3:stream_type_set", data)
      end

      def frame_created(stream_id:, type:, length: nil, frame: nil, headers: nil)
        @writer.record("http3:frame_created", { stream_id:, frame: frame_data(type, length, frame, headers) })
      end

      def frame_parsed(stream_id:, type:, length: nil, frame: nil, headers: nil)
        @writer.record("http3:frame_parsed", { stream_id:, frame: frame_data(type, length, frame, headers) })
      end

      def priority_updated(stream_id:, priority:)
        @writer.record("http3:priority_updated", { stream_id:, new: priority.to_field })
      end

      private def frame_data(type, length, frame, headers)
        data = {} #: Hash[Symbol, json]
        if (name = FRAME_TYPES[type])
          data[:frame_type] = name
        else
          data[:frame_type] = reserved?(type) || Frame::HTTP2_TYPES.include?(type) ? "reserved" : "unknown"
          data[:frame_type_bytes] = type
        end
        data.merge!(fields(headers)) if headers
        case frame
        when Frame::Settings then data[:settings] = frame.settings.first(MAX_FIELDS).map { |identifier, value| setting(identifier, value) }
        when Frame::GoAway then data[:id] = frame.id
        when Frame::CancelPush, Frame::MaxPushId, Frame::PushPromise then data[:push_id] = frame.push_id
        when Frame::PriorityUpdate
          data[frame.push ? :push_id : :stream_id] = frame.element_id
          data.merge!(field("priority_field_value", frame.priority))
        end
        data[:raw] = { payload_length: length } if length
        data
      end

      # The lines of a field section, MAX_FIELDS at most, the rest counted.
      private def fields(headers)
        lines = headers.first(MAX_FIELDS).map { |name, value| field("name", name).merge(field("value", value)) }
        result = { headers: lines } #: Hash[Symbol, json]
        result[:"raiha:headers_omitted"] = headers.size - MAX_FIELDS if headers.size > MAX_FIELDS
        result
      end

      # A name, a value or a Priority Field Value as text, or hex when it is
      # not, cut to MAX_FIELD_BYTES; its whole length when cut.
      private def field(key, bytes)
        cut = bytes.byteslice(0, MAX_FIELD_BYTES) || ""
        result = TEXT.match?(cut) ? { key.to_sym => text(cut) } : { :"#{key}_bytes" => cut.unpack1("H*") } #: Hash[Symbol, json]
        result[:"raiha:#{key}_length"] = bytes.bytesize if cut.bytesize < bytes.bytesize
        result
      end

      private def setting(identifier, value)
        if (name = SETTING_NAMES[identifier])
          { name:, value: }
        else
          { name: reserved?(identifier) ? "reserved" : "unknown", name_bytes: identifier, value: }
        end
      end

      # The identifiers 0x1f * N + 0x21, which HTTP/3 reserves to be ignored
      # (RFC 9114 "Reserved Stream Types", "Reserved Frame Types",
      # "Defined SETTINGS Parameters").
      private def reserved?(value) = value >= 0x21 && (value - 0x21) % 0x1f == 0

      # Bytes TEXT matched, as a String JSON takes.
      private def text(bytes) = bytes.dup.force_encoding(Encoding::UTF_8)
    end
  end
end
