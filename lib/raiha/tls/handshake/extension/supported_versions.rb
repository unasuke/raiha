require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # SupportedVersions
        #
        #   struct {
        #       select (Handshake.msg_type) {
        #           case client_hello:
        #                ProtocolVersion versions<2..254>;
        #
        #           case server_hello: /* and HelloRetryRequest */
        #                ProtocolVersion selected_version;
        #       };
        #   } SupportedVersions;
        # @see https://datatracker.ietf.org/doc/rfc8446/
        class SupportedVersions < AbstractExtension
          EXTENSION_TYPE_NUMBER = 43

          def self.generate_for_tls13
            self.new(on: :client_hello).tap do |ext| # message type independent
              ext.extension_data = "\x02\x03\x04"
            end
          end
        end
      end
    end
  end
end
