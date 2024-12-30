require_relative "../extension"
require_relative "abstract_extension"

class Raiha::TLS::Protocol::Handshake
  class Extension
    class RecordSizeLimit < AbstractExtension
      EXTENSION_TYPE_NUMBER = 28
    end
  end
end
