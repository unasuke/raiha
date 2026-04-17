require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # PskKeyExchangeModes Extension
        #
        #   enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
        #
        #   struct {
        #       PskKeyExchangeMode ke_modes<1..255>;
        #   } PskKeyExchangeModes;
        #
        # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.9
        class PskKeyExchangeModes < AbstractExtension
          EXTENSION_TYPE_NUMBER = 45

          MODES = {
            psk_ke: 0,
            psk_dhe_ke: 1,
          }.freeze

          attr_accessor :modes

          def initialize(on:)
            super
            @modes = [] #: Array[Symbol]
          end

          def extension_data=(data)
            super
            buf = StringIO.new(data)
            length = buf.read(1).unpack1("C")
            @modes = buf.read(length).unpack("C*").map { |m| MODES.key(m) }
          end

          def serialize
            buf = @modes.map { |m| MODES[m] }.pack("C*")
            ext_data = [buf.bytesize].pack("C") + buf
            [EXTENSION_TYPE_NUMBER].pack("n") + [ext_data.bytesize].pack("n") + ext_data
          end
        end
      end
    end
  end
end
