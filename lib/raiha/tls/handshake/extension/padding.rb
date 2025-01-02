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
            padding = self.new
            padding.length = length
            padding.extension_data = "\x00" * length
            padding
          end

          def serialize
            [EXTENSION_TYPE_NUMBER].pack("n") + [@extension_data.bytesize].pack("n") + @extension_data
          end
        end
      end
    end
  end
end
