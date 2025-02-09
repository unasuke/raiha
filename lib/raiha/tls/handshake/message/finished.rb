module Raiha
  module TLS
    class Handshake
      # Finished message
      #
      #   struct {
      #       opaque verify_data[Hash.length];
      #   } Finished;
      #
      # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
      class Finished < Message
        attr_accessor :verify_data

        def self.deserialize(data)
          finished = self.new
          finished.verify_data = data
          finished
        end

        def serialize
          verify_data
        end
      end
    end
  end
end
