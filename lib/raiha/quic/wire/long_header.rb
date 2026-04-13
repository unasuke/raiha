# frozen_string_literal: true

require_relative "header"

module Raiha::Quic
  module Wire
    class LongHeader < Header
      module PacketType
        INITIAL = 0x00
        ZERO_RTT = 0x01
        HANDSHAKE = 0x02
        RETRY = 0x03
      end

      attr_accessor :packet_type
      attr_accessor :version
      attr_accessor :destination_connection_id
      attr_accessor :source_connection_id
      attr_accessor :packet_number
      attr_accessor :packet_number_length
      attr_accessor :payload_length
      attr_accessor :token
      attr_accessor :retry_token
      attr_accessor :retry_integrity_tag

      def initialize
        @token = "".b
      end

      def long_header?
        true
      end

      def self.parse(buffer)
        header = self.new
        first_byte = buffer.read_uint8

        header.packet_type = (first_byte & 0x30) >> 4
        header.version = buffer.read_uint32

        dcid_length = buffer.read_uint8
        header.destination_connection_id = Protocol::ConnectionID.from_bytes(buffer.read(dcid_length))

        scid_length = buffer.read_uint8
        header.source_connection_id = Protocol::ConnectionID.from_bytes(buffer.read(scid_length))

        case header.packet_type
        when PacketType::INITIAL
          token_length = buffer.read_varint
          header.token = buffer.read(token_length) if token_length > 0
          header.payload_length = buffer.read_varint
          header.packet_number_length = (first_byte & 0x03) + 1

        when PacketType::ZERO_RTT, PacketType::HANDSHAKE
          header.payload_length = buffer.read_varint
          header.packet_number_length = (first_byte & 0x03) + 1

        when PacketType::RETRY
          remaining = buffer.remaining - 16
          header.retry_token = buffer.read(remaining)
          header.retry_integrity_tag = buffer.read(16)
        end

        header
      end

      def serialize
        buf = Buffer.new

        first_byte = LONG_HEADER_FORM | 0x40
        first_byte |= (@packet_type << 4)
        first_byte |= ((@packet_number_length || 1) - 1)
        buf.write_uint8(first_byte)

        buf.write_uint32(@version)

        buf.write_uint8(@destination_connection_id.length)
        buf.write(@destination_connection_id.serialize)
        buf.write_uint8(@source_connection_id.length)
        buf.write(@source_connection_id.serialize)

        case @packet_type
        when PacketType::INITIAL
          buf.write_varint(@token.bytesize)
          buf.write(@token) unless @token.empty?

        when PacketType::RETRY
          buf.write(@retry_token)
          buf.write(@retry_integrity_tag)
        end

        buf.to_s
      end

      def initial?
        @packet_type == PacketType::INITIAL
      end

      def zero_rtt?
        @packet_type == PacketType::ZERO_RTT
      end

      def handshake?
        @packet_type == PacketType::HANDSHAKE
      end

      def retry?
        @packet_type == PacketType::RETRY
      end
    end
  end
end
