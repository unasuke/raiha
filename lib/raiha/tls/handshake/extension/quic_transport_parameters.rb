# frozen_string_literal: true

require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # RFC 9001 Section 8.2
        # quic_transport_parameters extension (0x0039)
        class QuicTransportParameters < AbstractExtension
          EXTENSION_TYPE_NUMBER = 0x0039

          attr_accessor :transport_parameters_data

          def initialize(on:)
            super
            @transport_parameters_data = "".b
          end

          def extension_data=(data)
            @extension_data = data
            @transport_parameters_data = data
          end

          def serialize
            data = @transport_parameters_data || "".b
            [EXTENSION_TYPE_NUMBER].pack("n") + [data.bytesize].pack("n") + data
          end
        end
      end
    end
  end
end
