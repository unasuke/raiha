require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # @see https://datatracker.ietf.org/doc/rfc8446/
        class SignatureAlgorithms < AbstractExtension
          EXTENSION_TYPE_NUMBER = 13
        end
      end
    end
  end
end
