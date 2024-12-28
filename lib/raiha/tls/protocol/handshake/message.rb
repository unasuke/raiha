module Raiha::TLS::Protocol
  class Handshake
    class Message
      def serialize
        raise NotImplementedError
      end

      def self.deserialize(data:, type:)
        case type
        when Handshake::HANDSHAKE_TYPE[:client_hello]
          ClientHello.deserialize(data)
        else
          raise "unknown message type: #{type}"
        end
      end
    end
  end
end

require_relative "message/client_hello"
require_relative "message/server_hello"
