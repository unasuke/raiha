require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # @see https://datatracker.ietf.org/doc/rfc8446/
        class OidFilters < AbstractExtension
          EXTENSION_TYPE_NUMBER = 48
        end
      end
    end
  end
end
