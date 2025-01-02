require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # @see https://datatracker.ietf.org/doc/rfc8446/
        class PreSharedKey < AbstractExtension
          EXTENSION_TYPE_NUMBER = 41
        end
      end
    end
  end
end
