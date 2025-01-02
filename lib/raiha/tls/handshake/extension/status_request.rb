require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # @see https://datatracker.ietf.org/doc/rfc6066/
        class StatusRequest < AbstractExtension
          EXTENSION_TYPE_NUMBER = 5
        end
      end
    end
  end
end
