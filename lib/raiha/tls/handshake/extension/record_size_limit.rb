require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # @see https://datatracker.ietf.org/doc/rfc8449/
        class RecordSizeLimit < AbstractExtension
          EXTENSION_TYPE_NUMBER = 28
        end
      end
    end
  end
end
