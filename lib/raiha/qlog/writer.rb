# frozen_string_literal: true

require "json"

module Raiha
  module Qlog
    # Top-level constants per draft-ietf-quic-qlog-main-schema-13
    FILE_SCHEMA_CONTAINED = "urn:ietf:params:qlog:file:contained"
    FILE_SCHEMA_SEQUENTIAL = "urn:ietf:params:qlog:file:sequential"
    SERIALIZATION_JSON = "application/qlog+json"
    SERIALIZATION_JSON_SEQ = "application/qlog+json-seq"

    # Per draft-ietf-quic-qlog-quic-events-12
    QUIC_EVENT_SCHEMA = "urn:ietf:params:qlog:events:quic"

    EPOCH_DEFAULT = "1970-01-01T00:00:00.000Z"

    # JSON format qlog writer per draft-ietf-quic-qlog-main-schema-13
    class Writer
      attr_reader :reference_time

      def initialize(output:, title: nil, description: nil)
        @output = output
        @title = title
        @description = description
        @traces = [] #: Array[Hash[Symbol, untyped]]
        @current_trace = nil
        @reference_time = Time.now
      end

      def start_trace(vantage_point:, connection_id:)
        @current_trace = {
          title: "Connection #{connection_id}",
          vantage_point: {
            name: vantage_point.to_s,
            type: vantage_point == :client ? "client" : "server"
          },
          event_schemas: [QUIC_EVENT_SCHEMA],
          common_fields: {
            time_format: "relative_to_epoch",
            reference_time: {
              clock_type: "system",
              epoch: EPOCH_DEFAULT
            }
          },
          events: [] #: Array[Hash[Symbol, untyped]]
        }
        @traces << @current_trace
      end

      def log(event)
        return unless @current_trace

        event_data = event.to_h
        event_data[:time] = ((event.time - @reference_time) * 1000).round(3)
        @current_trace[:events] << event_data
      end

      def flush
        qlog = {
          file_schema: FILE_SCHEMA_CONTAINED,
          serialization_format: SERIALIZATION_JSON,
          title: @title,
          description: @description,
          traces: @traces
        }.compact

        case @output
        when IO, StringIO
          @output.write(JSON.pretty_generate(qlog))
        when String
          File.write(@output, JSON.pretty_generate(qlog))
        end
      end

      def self.to_file(path, title: nil, &block)
        writer = self.new(output: path, title: title)
        yield writer
        writer.flush
      end
    end

    # JSON-SEQ streaming writer per draft-ietf-quic-qlog-main-schema-13 §5
    class StreamingWriter
      attr_reader :reference_time

      def initialize(output:)
        @output = output
        @reference_time = Time.now
        write_header
      end

      def start_trace(vantage_point:, connection_id:)
        trace_header = {
          title: "Connection #{connection_id}",
          vantage_point: {
            name: vantage_point.to_s,
            type: vantage_point == :client ? "client" : "server"
          },
          event_schemas: [QUIC_EVENT_SCHEMA],
          common_fields: {
            time_format: "relative_to_epoch",
            reference_time: {
              clock_type: "system",
              epoch: EPOCH_DEFAULT
            }
          }
        }
        @output.puts(JSON.generate(trace_header))
        @output.flush
      end

      def log(event)
        event_data = event.to_h
        event_data[:time] = ((event.time - @reference_time) * 1000).round(3)
        @output.puts(JSON.generate(event_data))
        @output.flush
      end

      def flush
        @output.flush
      end

      private def write_header
        header = {
          file_schema: FILE_SCHEMA_SEQUENTIAL,
          serialization_format: SERIALIZATION_JSON_SEQ
        }
        @output.puts(JSON.generate(header))
        @output.flush
      end
    end
  end
end
