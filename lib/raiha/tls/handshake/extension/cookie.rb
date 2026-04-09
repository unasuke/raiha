require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # Cookie Extension
        #
        #   struct {
        #       opaque cookie<1..2^16-1>;
        #   } Cookie;
        #
        # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.2
        class Cookie < AbstractExtension
          EXTENSION_TYPE_NUMBER = 44

          attr_accessor :cookie

          def extension_data=(data)
            super
            buf = StringIO.new(data)
            length = buf.read(2).unpack1("n")
            @cookie = buf.read(length)
          end

          def serialize
            buf = [@cookie.bytesize].pack("n") + @cookie
            [EXTENSION_TYPE_NUMBER].pack("n") + [buf.bytesize].pack("n") + buf
          end
        end
      end
    end
  end
end
