require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # EarlyData Extension
        #
        # In ClientHello and EncryptedExtensions: empty extension_data
        # In NewSessionTicket:
        #   struct {
        #       uint32 max_early_data_size;
        #   } EarlyDataIndication;
        #
        # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.10
        class EarlyData < AbstractExtension
          EXTENSION_TYPE_NUMBER = 42

          attr_accessor :max_early_data_size
          attr_accessor :context

          def extension_data=(data)
            super
            if data.bytesize >= 4
              @max_early_data_size = data.unpack1("N")
              @context = :new_session_ticket
            end
          end

          def serialize
            case @context
            when :new_session_ticket
              buf = [@max_early_data_size].pack("N")
              [EXTENSION_TYPE_NUMBER].pack("n") + [buf.bytesize].pack("n") + buf
            else
              [EXTENSION_TYPE_NUMBER].pack("n") + [0].pack("n")
            end
          end
        end
      end
    end
  end
end
