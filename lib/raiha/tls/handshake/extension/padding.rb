require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # @see https://datatracker.ietf.org/doc/rfc7685/
        class Padding < AbstractExtension
          EXTENSION_TYPE_NUMBER = 21

          attr_accessor :length

          def self.generate_padding_with_length(length)
            if length < 0 || length > 65535
              raise "Padding length must be between 0 and 65535"
            end

            # padding extension is only available in client hello
            # @see https://www.ietf.org/archive/id/draft-ietf-tls-rfc8446bis-11.html#table-1
            padding = self.new(on: :client_hello)
            padding.length = length
            padding.extension_data = "\x00" * length
            padding
          end
        end
      end
    end
  end
end
