require_relative "../extension"
require_relative "abstract_extension"

class Raiha::TLS::Protocol::Handshake
  class Extension
    # @see https://datatracker.ietf.org/doc/rfc7301/
    class ApplicationLayerProtocolNegotiation < AbstractExtension
      EXTENSION_TYPE_NUMBER = 16
    end
  end
end
