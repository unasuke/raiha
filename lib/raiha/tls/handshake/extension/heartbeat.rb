require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # @see https://datatracker.ietf.org/doc/rfc6520/
        class Heartbeat < AbstractExtension
          EXTENSION_TYPE_NUMBER = 15
        end
      end
    end
  end
end
