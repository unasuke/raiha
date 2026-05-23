# frozen_string_literal: true

require_relative "header"
require_relative "../error"

module Raiha::Quic
  module Wire
    class ShortHeader < Header
      attr_accessor :destination_connection_id
      attr_accessor :packet_number
      attr_accessor :packet_number_length
      attr_accessor :key_phase
      attr_accessor :spin_bit

      def long_header?
        false
      end

      def self.parse(buffer, connection_id_length:)
        header = self.new
        first_byte = buffer.read_uint8

        header.spin_bit = (first_byte & 0x20) != 0
        header.key_phase = (first_byte & 0x04) != 0
        header.packet_number_length = (first_byte & 0x03) + 1

        header.destination_connection_id = Protocol::ConnectionID.from_bytes(
          buffer.read(connection_id_length)
        )

        header
      end

      def serialize
        buf = Buffer.new

        first_byte = 0x40
        first_byte |= 0x20 if @spin_bit
        first_byte |= 0x04 if @key_phase
        first_byte |= ((@packet_number_length || 1) - 1)
        buf.write_uint8(first_byte)

        cid = @destination_connection_id or raise Raiha::Quic::Error, "TODO: destination_connection_id not set"
        buf.write(cid.serialize)

        buf.to_s
      end
    end
  end
end
