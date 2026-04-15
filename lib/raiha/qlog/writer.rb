# frozen_string_literal: true

require "json"

module Raiha
  module Qlog
    # JSON format qlog writer per draft-ietf-quic-qlog-main-schema
    class Writer
      QLOG_VERSION = "0.4"

      attr_reader :reference_time

      def initialize(output:, title: nil, description: nil)
        @output = output
        @title = title
        @description = description
        @traces = []
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
          common_fields: {
            protocol_type: "QUIC",
            time_format: "relative",
            reference_time: (@reference_time.to_f * 1000).to_i
          },
          events: []
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
          qlog_version: QLOG_VERSION,
          qlog_format: "JSON",
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

    # NDJSON format streaming writer per draft-ietf-quic-qlog-main-schema
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
          common_fields: {
            protocol_type: "QUIC",
            time_format: "relative",
            reference_time: (@reference_time.to_f * 1000).to_i
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
          qlog_version: Writer::QLOG_VERSION,
          qlog_format: "JSON-SEQ"
        }
        @output.puts(JSON.generate(header))
        @output.flush
      end
    end
  end
end
