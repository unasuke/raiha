require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # @see https://datatracker.ietf.org/doc/rfc5077/
        # @see https://datatracker.ietf.org/doc/rfc8447/
        class SessionTicket < AbstractExtension
          EXTENSION_TYPE_NUMBER = 35
        end
      end
    end
  end
end
