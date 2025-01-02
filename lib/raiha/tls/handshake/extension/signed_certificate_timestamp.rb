require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # @see https://datatracker.ietf.org/doc/rfc6962/
        class SignedCertificateTimestamp < AbstractExtension
          EXTENSION_TYPE_NUMBER = 18
        end
      end
    end
  end
end
