require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # @see https://datatracker.ietf.org/doc/rfc5764/
        class UseSrtp < AbstractExtension
          EXTENSION_TYPE_NUMBER = 14
        end
      end
    end
  end
end
