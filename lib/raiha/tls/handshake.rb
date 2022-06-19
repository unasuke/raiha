require 'raiha/tls/base'

module Raiha
  module Tls
    class Handshake < Base
      def parse
        byte :msg_type, size: 1, type: :int
        byte :len, size: 3, type: :int
        byte :body, size: :len

        self
      end

      def msg_type
        case @parsed[:msg_type][:value]
        when 1 then :client_hello
        when 2 then :server_hello
        when 4 then :new_session_ticket
        when 5 then :end_of_early_data
        when 8 then :encrypted_extentions
        when 11 then :certificate
        when 13 then :certificate_request
        when 15 then :certificate_verify
        when 20 then :finished
        when 24 then :key_update
        when 254 then :message_hash
        end
      end
    end
  end
end
