module Raiha
  module TLS
    class Handshake
      class Message
        def serialize
          raise NotImplementedError
        end

        def self.deserialize(data:, type:)
          case type
          when Handshake::HANDSHAKE_TYPE[:client_hello]
            ClientHello.deserialize(data)
          when Handshake::HANDSHAKE_TYPE[:server_hello]
            ServerHello.deserialize(data)
          when Handshake::HANDSHAKE_TYPE[:encrypted_extensions]
            EncryptedExtensions.deserialize(data)
          when Handshake::HANDSHAKE_TYPE[:certificate]
            Certificate.deserialize(data)
          else
            raise "unknown message type: #{type}"
          end
        end
      end
    end
  end
end

require_relative "message/client_hello"
require_relative "message/server_hello"
require_relative "message/encrypted_extensions"
require_relative "message/certificate"
