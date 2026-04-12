# frozen_string_literal: true

module Raiha::Quic
  module Protocol
    module Version
      V1 = 0x00000001
      V2 = 0x6b3343cf
      VERSION_NEGOTIATION = 0x00000000

      SUPPORTED_VERSIONS = [V1, V2].freeze

      def self.supported?(version)
        SUPPORTED_VERSIONS.include?(version)
      end

      def self.to_s(version)
        case version
        when V1 then "QUIC v1"
        when V2 then "QUIC v2"
        when VERSION_NEGOTIATION then "Version Negotiation"
        else "Unknown (0x#{version.to_s(16)})"
        end
      end
    end
  end
end
