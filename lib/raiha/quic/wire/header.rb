# frozen_string_literal: true

require_relative "buffer"
require_relative "../error"
require_relative "../protocol/connection_id"

module Raiha::Quic
  module Wire
    class Header
      LONG_HEADER_FORM = 0x80

      attr_reader :destination_connection_id
      attr_reader :packet_number

      def self.parse(buffer)
        first_byte = buffer.read_uint8
        buffer.seek(buffer.pos - 1)

        if (first_byte & LONG_HEADER_FORM) != 0
          LongHeader.parse(buffer)
        else
          raise Raiha::Quic::Error, "ShortHeader.parse requires connection_id_length"
        end
      end

      def long_header?
        raise NotImplementedError
      end

      def short_header?
        !long_header?
      end
    end
  end
end
