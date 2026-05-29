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
    # Minimal HTTP/3 client that runs on top of a Raiha::Connection.
    # Callers are expected to drive the connection I/O loop externally.
    class Client
      def initialize(connection:)
        @connection = connection
        @encoder = QPACK::Encoder.new
        @decoder = QPACK::Decoder.new
        @control_stream = nil
        @qpack_encoder_stream = nil
        @qpack_decoder_stream = nil
      end

      # Open the local control stream and send an initial SETTINGS frame (RFC 9114 Section 6.2.1).
      # Must be called after the QUIC handshake completes.
      def setup_control_stream(settings: default_settings) # steep:ignore MethodBodyTypeMismatch
        settings_frame = SettingsFrame.new
        settings.each { |id, value| settings_frame.settings[id] = value }
        @control_stream = open_unidirectional_with_type(StreamType::CONTROL, extra_data: settings_frame.serialize)
        @control_stream
      end

      # Open the local QPACK encoder and decoder unidirectional streams
      # (RFC 9204 Section 4.2). raiha runs QPACK in static-only mode, so
      # neither stream carries any QPACK instructions, but stricter peers
      # (e.g. nghttp3) expect both streams to exist. Must be called after
      # setup_control_stream.
      def setup_qpack_streams
        @qpack_encoder_stream = open_unidirectional_with_type(StreamType::QPACK_ENCODER)
        @qpack_decoder_stream = open_unidirectional_with_type(StreamType::QPACK_DECODER)
        nil
      end

      # Open a unidirectional stream and prepend its HTTP/3 stream type
      # varint (RFC 9114 Section 6.2). `extra_data` is concatenated after
      # the type byte so the whole payload reaches the peer in a single
      # send_stream_data call, avoiding the 2-call pattern that would
      # require manual offset tracking on the caller side.
      private def open_unidirectional_with_type(type, extra_data: nil)
        stream = @connection.open_stream(bidirectional: false)
        payload = Quic::Varint.encode(type)
        payload = payload + extra_data if extra_data
        @connection.send_stream_data(stream.stream_id.value, payload)
        stream
      end

      private def default_settings
        {
          SettingsFrame::SETTINGS[:qpack_max_table_capacity] => 0,
          SettingsFrame::SETTINGS[:qpack_blocked_streams] => 0,
        }
      end

      public

      # Prepare an HTTP/3 request over a new bidirectional stream. Returns the opened stream
      # so the caller can drive the connection to flush/receive and then call receive_response.
      def send_request(method:, scheme:, authority:, path:, headers: [], body: nil)
        request_headers = [
          [":method", method.to_s],
          [":scheme", scheme.to_s],
          [":authority", authority.to_s],
          [":path", path.to_s],
        ] + headers

        encoded_headers = @encoder.encode(request_headers)
        headers_frame = HeadersFrame.new(encoded_headers)

        stream = @connection.open_stream(bidirectional: true)
        payload = headers_frame.serialize.dup
        payload << DataFrame.new(body).serialize if body && !body.empty?

        @connection.send_stream_data(stream.stream_id.value, payload, fin: true)
        stream
      end

      # Parse the peer's control stream payload and return the peer's SETTINGS, or nil.
      def receive_peer_control_stream(stream)
        data = stream.read
        _, frames = ControlStream.parse_incoming(data)
        ControlStream.extract_settings(frames)
      end

      # Parse frames from a stream's receive buffer and build a Response object.
      # Assumes the stream has received complete HEADERS + optional DATA frames with FIN.
      def receive_response(stream)
        data = stream.read
        buffer = Quic::Wire::Buffer.new(data)

        response = Response.new
        body = String.new(encoding: "BINARY")
        until buffer.eof?
          frame = Frame.parse(buffer)
          case frame
          when HeadersFrame
            response.headers = @decoder.decode(frame.encoded_field_section)
          when DataFrame
            body << frame.data
          end
        end
        response.body = body
        response
      end
    end
  end
end
