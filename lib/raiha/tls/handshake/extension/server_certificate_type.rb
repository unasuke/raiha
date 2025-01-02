require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # @see https://datatracker.ietf.org/doc/rfc7250/
        class ServerCertificateType < AbstractExtension
          EXTENSION_TYPE_NUMBER = 20
        end
      end
    end
  end
end
