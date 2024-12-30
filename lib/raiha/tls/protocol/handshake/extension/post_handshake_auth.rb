require_relative "../extension"
require_relative "abstract_extension"

class Raiha::TLS::Protocol::Handshake
  class Extension
    # @see https://datatracker.ietf.org/doc/rfc8446/
    class PostHandshakeAuth < AbstractExtension
      EXTENSION_TYPE_NUMBER = 49
    end
  end
end
