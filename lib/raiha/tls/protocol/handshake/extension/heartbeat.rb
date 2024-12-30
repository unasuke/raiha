require_relative "../extension"
require_relative "abstract_extension"

class Raiha::TLS::Protocol::Handshake
  class Extension
    # @see https://datatracker.ietf.org/doc/rfc6520/
    class Heartbeat < AbstractExtension
      EXTENSION_TYPE_NUMBER = 15
    end
  end
end
