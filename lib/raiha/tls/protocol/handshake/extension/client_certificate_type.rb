require_relative "../extension"
require_relative "abstract_extension"

class Raiha::TLS::Protocol::Handshake
  class Extension
    # @see https://datatracker.ietf.org/doc/rfc7250/
    class ClientCertificateType < AbstractExtension
      EXTENSION_TYPE_NUMBER = 19
    end
  end
end
