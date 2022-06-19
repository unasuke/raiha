
require 'raiha/packet/base'

module Raiha
  module Packet
    class VersionNegotaiation < Base
      # https://www.rfc-editor.org/rfc/rfc9000#version-negotiation
      def parse
        bit :header_form, size: 1, type: :raw
        bit :unused, size: 7, type: :raw
        bit :version, size: 30, type: :raw # zero
        bit :destination_connection_id_length, size: 8, type: :int
        bit :destination_connection_id, size: :destination_connection_id_length
        bit :source_connection_id_length, size: 8, type: :int
        bit :source_connection_id, size: :source_connection_id_length
        bit :supported_version, size: 32
      end
    end
  end
end
