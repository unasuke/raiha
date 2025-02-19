require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # @see https://datatracker.ietf.org/doc/rfc6066/
        class ServerName < AbstractExtension
          EXTENSION_TYPE_NUMBER = 0
          attr_accessor :server_name

          def extension_data=(data)
            super
            @server_name = @extension_data
          end
        end
      end
    end
  end
end
