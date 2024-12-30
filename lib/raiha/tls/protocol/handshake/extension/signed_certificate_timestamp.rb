require_relative "../extension"
require_relative "abstract_extension"

class Raiha::TLS::Protocol::Handshake
  class Extension
    # @see https://datatracker.ietf.org/doc/rfc6962/
    class SignedCertificateTimestamp < AbstractExtension
      EXTENSION_TYPE_NUMBER = 18
    end
  end
end

