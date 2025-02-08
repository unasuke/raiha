module Raiha
  module TLS
    class Handshake
      # EncryptedExtensions message
      #
      #  struct {
      #      Extension extensions<0..2^16-1>;
      #  } EncryptedExtensions;
      #
      # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.1
      class EncryptedExtensions < Message
        attr_accessor :extensions

        def self.deserialize(data)
          ee = self.new
          buf = StringIO.new(data)
          extensions_bytesize = buf.read(2).unpack1("n")
          ee.extensions = Extension.deserialize_extensions(buf.read(extensions_bytesize), type: :encrypted_extensions)
          ee
        end
      end
    end
  end
end
