module Raiha::TLS::Protocol
  class Handshake
    class ServerHello < Message
      attr_accessor :random
      attr_accessor :legacy_session_id_echo
      attr_accessor :cipher_suite
      attr_accessor :extensions
    end
  end
end
