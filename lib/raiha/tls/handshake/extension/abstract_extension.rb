module Raiha
  module TLS
    class Handshake
      class Extension
        # Abstract class of each extensions.
        # Defines `extension_data` accessor method only.
        # Each properties of each extensions (e.g. `server_name`, `supported_groups`, etc.) are defined in each extension classes.
        class AbstractExtension
          EXTENSION_TYPE_NUMBER = nil # If not override this const, #serialize method will raise error.

          attr_reader :extension_data

          def extension_data=(data)
            # TODO: extension specific validation
            @extension_data = data
          end

          def serialize
            [self.class::EXTENSION_TYPE_NUMBER].pack("n") + [@extension_data.bytesize].pack("n") + @extension_data
          end
        end
      end
    end
  end
end
