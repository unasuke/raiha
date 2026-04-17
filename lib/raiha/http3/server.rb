# frozen_string_literal: true

require_relative "../quic/wire/buffer"
require_relative "frame"
require_relative "qpack/encoder"
require_relative "qpack/decoder"
require_relative "request"
require_relative "response"
require_relative "stream_type"
require_relative "control_stream"

module Raiha
  module HTTP3
    # Minimal HTTP/3 server that runs on top of a Raiha::Connection.
    # Callers are expected to drive the connection I/O loop externally.
    class Server
      def initialize(connection:)
        @connection = connection
        @encoder = QPACK::Encoder.new
        @decoder = QPACK::Decoder.new
        @control_stream = nil
      end

      # Open the local control stream and send an initial SETTINGS frame (RFC 9114 Section 6.2.1).
      # Must be called after the QUIC handshake completes.
      def setup_control_stream(settings: default_settings)
        @control_stream = @connection.open_stream(bidirectional: false)
        settings_frame = SettingsFrame.new
        settings.each { |id, value| settings_frame.settings[id] = value }

        payload = Quic::Varint.encode(StreamType::CONTROL) + settings_frame.serialize
        @connection.send_stream_data(@control_stream.stream_id.value, payload)
        @control_stream
      end

      private def default_settings
        {
          SettingsFrame::SETTINGS[:qpack_max_table_capacity] => 0,
          SettingsFrame::SETTINGS[:qpack_blocked_streams] => 0,
        }
      end

      public

      # Parse the peer's control stream payload and return the peer's SETTINGS, or nil.
      def receive_peer_control_stream(stream)
        data = stream.read
        _, frames = ControlStream.parse_incoming(data)
        ControlStream.extract_settings(frames)
      end

      # Parse frames from a stream's receive buffer and build a Request object.
      def receive_request(stream)
        data = stream.read
        buffer = Quic::Wire::Buffer.new(data)

        request = Request.new
        body = String.new(encoding: "BINARY")
        until buffer.eof?
          frame = Frame.parse(buffer)
          case frame
          when HeadersFrame
            request.headers = @decoder.decode(frame.encoded_field_section)
          when DataFrame
            body << frame.data
          end
        end
        request.body = body
        request
      end

      # Send an HTTP/3 response on the given stream.
      def send_response(stream, status:, headers: [], body: nil)
        response_headers = [[":status", status.to_s]] + headers
        encoded_headers = @encoder.encode(response_headers)
        headers_frame = HeadersFrame.new(encoded_headers)

        payload = headers_frame.serialize.dup
        payload << DataFrame.new(body).serialize if body && !body.empty?

        @connection.send_stream_data(stream.stream_id.value, payload, fin: true)
      end
    end
  end
end
