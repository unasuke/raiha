require 'raiha/packet/base'

module Raiha
  module Packet
    class Handshake < Base
      def parse
        bit :header_form, size: 1, type: :raw
        bit :fixed_bit, size: 1, type: :raw
        bit :long_packet_type, size: 2, type: :raw
        bit :reserved_bits, size: 2, type: :raw
        bit :packet_number_length, size: 2, type: :int
        bit :version, size: 32, type: :int
        bit :destination_connection_id_length, size: 8, type: :int
        byte :destination_connection_id, size: :destination_connection_id_length
        bit :source_connection_id_length, size: 8, type: :int
        byte :source_connection_id, size: :source_connection_id_length
        bit :length
        byte :packet_number, size: @parsed[:packet_number_length][:value] + 1, type: :int
      end
    end
  end
end
