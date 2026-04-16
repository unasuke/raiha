# frozen_string_literal: true

require_relative "../quic/wire/buffer"
require_relative "../quic/varint"

module Raiha
  module HTTP3
    # RFC 9114 Section 7: HTTP/3 Frame Format
    #
    # HTTP Frame {
    #   Type (i),
    #   Length (i),
    #   Frame Payload (..),
    # }
    class Frame
      # RFC 9114 Section 7.2: Frame Types
      module Type
        DATA = 0x00
        HEADERS = 0x01
        CANCEL_PUSH = 0x03
        SETTINGS = 0x04
        PUSH_PROMISE = 0x05
        GOAWAY = 0x07
        MAX_PUSH_ID = 0x0d
      end

      attr_reader :frame_type

      def self.parse(buffer)
        frame_type = buffer.read_varint
        length = buffer.read_varint
        payload = buffer.read(length)

        case frame_type
        when Type::DATA
          DataFrame.deserialize(payload)
        when Type::HEADERS
          HeadersFrame.deserialize(payload)
        when Type::CANCEL_PUSH
          CancelPushFrame.deserialize(payload)
        when Type::SETTINGS
          SettingsFrame.deserialize(payload)
        when Type::PUSH_PROMISE
          PushPromiseFrame.deserialize(payload)
        when Type::GOAWAY
          GoawayFrame.deserialize(payload)
        when Type::MAX_PUSH_ID
          MaxPushIdFrame.deserialize(payload)
        else
          UnknownFrame.new(frame_type, payload)
        end
      end

      def serialize
        payload_bytes = serialize_payload
        buf = Quic::Wire::Buffer.new
        buf.write_varint(@frame_type)
        buf.write_varint(payload_bytes.bytesize)
        buf.write(payload_bytes)
        buf.to_s
      end

      private def serialize_payload
        raise NotImplementedError
      end
    end

    # RFC 9114 Section 7.2.1: DATA frames convey arbitrary, variable-length data
    class DataFrame < Frame
      attr_accessor :data

      def initialize(data = "".b)
        @frame_type = Type::DATA
        @data = data
      end

      def self.deserialize(payload)
        new(payload)
      end

      private def serialize_payload
        @data
      end
    end

    # RFC 9114 Section 7.2.2: HEADERS frames carry an encoded header list
    class HeadersFrame < Frame
      attr_accessor :encoded_field_section

      def initialize(encoded = "".b)
        @frame_type = Type::HEADERS
        @encoded_field_section = encoded
      end

      def self.deserialize(payload)
        new(payload)
      end

      private def serialize_payload
        @encoded_field_section
      end
    end

    # RFC 9114 Section 7.2.3: CANCEL_PUSH cancels a server push
    class CancelPushFrame < Frame
      attr_accessor :push_id

      def initialize(push_id = 0)
        @frame_type = Type::CANCEL_PUSH
        @push_id = push_id
      end

      def self.deserialize(payload)
        buf = Quic::Wire::Buffer.new(payload)
        new(buf.read_varint)
      end

      private def serialize_payload
        Quic::Varint.encode(@push_id)
      end
    end

    # RFC 9114 Section 7.2.4: SETTINGS frame
    class SettingsFrame < Frame
      # RFC 9114 Section 7.2.4.1 + RFC 9204 Section 5
      SETTINGS = {
        qpack_max_table_capacity: 0x01,
        max_field_section_size: 0x06,
        qpack_blocked_streams: 0x07,
      }.freeze

      attr_accessor :settings

      def initialize
        @frame_type = Type::SETTINGS
        @settings = {}
      end

      def self.deserialize(payload)
        frame = new
        buf = Quic::Wire::Buffer.new(payload)
        until buf.eof?
          id = buf.read_varint
          value = buf.read_varint
          frame.settings[id] = value
        end
        frame
      end

      def max_field_section_size
        @settings[SETTINGS[:max_field_section_size]]
      end

      def qpack_max_table_capacity
        @settings[SETTINGS[:qpack_max_table_capacity]] || 0
      end

      def qpack_blocked_streams
        @settings[SETTINGS[:qpack_blocked_streams]] || 0
      end

      private def serialize_payload
        buf = Quic::Wire::Buffer.new
        @settings.each do |id, value|
          buf.write_varint(id)
          buf.write_varint(value)
        end
        buf.to_s
      end
    end

    # RFC 9114 Section 7.2.5: PUSH_PROMISE frame (server push)
    class PushPromiseFrame < Frame
      attr_accessor :push_id, :encoded_field_section

      def initialize(push_id = 0, encoded = "".b)
        @frame_type = Type::PUSH_PROMISE
        @push_id = push_id
        @encoded_field_section = encoded
      end

      def self.deserialize(payload)
        buf = Quic::Wire::Buffer.new(payload)
        push_id = buf.read_varint
        encoded = buf.read(buf.remaining)
        new(push_id, encoded)
      end

      private def serialize_payload
        Quic::Varint.encode(@push_id) + @encoded_field_section
      end
    end

    # RFC 9114 Section 7.2.6: GOAWAY frame
    class GoawayFrame < Frame
      attr_accessor :stream_id

      def initialize(stream_id = 0)
        @frame_type = Type::GOAWAY
        @stream_id = stream_id
      end

      def self.deserialize(payload)
        buf = Quic::Wire::Buffer.new(payload)
        new(buf.read_varint)
      end

      private def serialize_payload
        Quic::Varint.encode(@stream_id)
      end
    end

    # RFC 9114 Section 7.2.7: MAX_PUSH_ID frame
    class MaxPushIdFrame < Frame
      attr_accessor :push_id

      def initialize(push_id = 0)
        @frame_type = Type::MAX_PUSH_ID
        @push_id = push_id
      end

      def self.deserialize(payload)
        buf = Quic::Wire::Buffer.new(payload)
        new(buf.read_varint)
      end

      private def serialize_payload
        Quic::Varint.encode(@push_id)
      end
    end

    # Catch-all for frame types not recognized (may be reserved or extension frames)
    class UnknownFrame < Frame
      attr_reader :payload

      def initialize(frame_type, payload)
        @frame_type = frame_type
        @payload = payload
      end

      private def serialize_payload
        @payload
      end
    end
  end
end
