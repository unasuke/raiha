require_relative "../extension"
require_relative "abstract_extension"

class Raiha::TLS::Protocol::Handshake
  class Extension
    # @see https://datatracker.ietf.org/doc/rfc8446/
    class PreSharedKey < AbstractExtension
      EXTENSION_TYPE_NUMBER = 41
    end
  end
end
