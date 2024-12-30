require_relative "../extension"
require_relative "abstract_extension"

class Raiha::TLS::Protocol::Handshake
  class Extension
    # @see https://datatracker.ietf.org/doc/rfc8446/
    class CertificateAuthorities < AbstractExtension
      EXTENSION_TYPE_NUMBER = 47
    end
  end
end
