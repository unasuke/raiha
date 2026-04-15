require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # @see https://datatracker.ietf.org/doc/rfc7301/
        class ApplicationLayerProtocolNegotiation < AbstractExtension
          EXTENSION_TYPE_NUMBER = 16

          attr_accessor :protocol_names

          def initialize(on:)
            super
            @protocol_names = []
          end

          def extension_data=(data)
            @extension_data = data
            buf = StringIO.new(data)
            list_length = buf.read(2).unpack1("n")
            list_data = buf.read(list_length)
            list_buf = StringIO.new(list_data)
            @protocol_names = []
            until list_buf.eof?
              name_length = list_buf.read(1).unpack1("C")
              @protocol_names << list_buf.read(name_length)
            end
          end

          def serialize
            list = @protocol_names.map { |name| [name.bytesize].pack("C") + name }.join
            data = [list.bytesize].pack("n") + list
            [EXTENSION_TYPE_NUMBER].pack("n") + [data.bytesize].pack("n") + data
          end
        end
      end
    end
  end
end
