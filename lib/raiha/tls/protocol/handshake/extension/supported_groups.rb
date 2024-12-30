require_relative "../extension"
require_relative "abstract_extension"

class Raiha::TLS::Protocol::Handshake
  class Extension
    # @see https://datatracker.ietf.org/doc/rfc7919/
    class SupportedGroups < AbstractExtension
      EXTENSION_TYPE_NUMBER = 10
    end
  end
end

