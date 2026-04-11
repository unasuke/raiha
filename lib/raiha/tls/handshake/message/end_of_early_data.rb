module Raiha
  module TLS
    class Handshake
      # EndOfEarlyData message
      #
      #   struct {} EndOfEarlyData;
      #
      # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.5
      class EndOfEarlyData < Message
        def self.deserialize(_data)
          self.new
        end

        def serialize
          ""
        end
      end
    end
  end
end
