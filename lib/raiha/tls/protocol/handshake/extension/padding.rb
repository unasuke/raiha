require_relative "../extension"
require_relative "abstract_extension"

class Raiha::TLS::Protocol::Handshake
  class Extension
    # @see https://datatracker.ietf.org/doc/rfc7685/
    class Padding < AbstractExtension
      EXTENSION_TYPE_NUMBER = 21
    end
  end
end
