module Raiha
  module TLS
    class Handshake
      # KeyUpdate message
      #
      #   enum {
      #       update_not_requested(0), update_requested(1), (255)
      #   } KeyUpdateRequest;
      #
      #   struct {
      #       KeyUpdateRequest request_update;
      #   } KeyUpdate;
      #
      # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.3
      class KeyUpdate < Message
        REQUEST_UPDATE = {
          update_not_requested: 0,
          update_requested: 1,
        }.freeze

        attr_accessor :request_update

        def initialize
          @request_update = :update_not_requested
        end

        def self.deserialize(data)
          key_update = new
          key_update.request_update = REQUEST_UPDATE.key(data.unpack1("C"))
          key_update
        end

        def serialize
          [REQUEST_UPDATE[@request_update]].pack("C")
        end
      end
    end
  end
end
