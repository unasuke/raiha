require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # @see https://datatracker.ietf.org/doc/rfc7301/
        class ApplicationLayerProtocolNegotiation < AbstractExtension
          EXTENSION_TYPE_NUMBER = 16
        end
      end
    end
  end
end
