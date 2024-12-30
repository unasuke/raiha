require_relative "../extension"
require_relative "abstract_extension"

class Raiha::TLS::Protocol::Handshake
  class Extension
    # @see https://datatracker.ietf.org/doc/rfc6066/
    class StatusRequest < AbstractExtension
      EXTENSION_TYPE_NUMBER = 5
    end
  end
end

