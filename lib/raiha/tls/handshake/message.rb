module Raiha
  module TLS
    class Handshake
      class Message
        def serialize
          raise NoMethodError
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
          when Handshake::HANDSHAKE_TYPE[:certificate_request]
            CertificateRequest.deserialize(data)
          when Handshake::HANDSHAKE_TYPE[:certificate_verify]
            CertificateVerify.deserialize(data)
          when Handshake::HANDSHAKE_TYPE[:finished]
            Finished.deserialize(data)
          when Handshake::HANDSHAKE_TYPE[:new_session_ticket]
            NewSessionTicket.deserialize(data)
          when Handshake::HANDSHAKE_TYPE[:key_update]
            KeyUpdate.deserialize(data)
          when Handshake::HANDSHAKE_TYPE[:end_of_early_data]
            EndOfEarlyData.deserialize(data)
          else
            puts "unknown message type: #{type}"
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
require_relative "message/certificate_request"
require_relative "message/certificate_verify"
require_relative "message/new_session_ticket"
require_relative "message/finished"
require_relative "message/key_update"
require_relative "message/end_of_early_data"
