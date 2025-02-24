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

          attr_accessor :protocol_versions

          def self.generate_for_tls13(on: :client_hello)
            case on
            when :client_hello
              self.new(on: :client_hello).tap do |ext|
                ext.extension_data = "\x02\x03\x04"
              end
            when :server_hello
              self.new(on: :server_hello).tap do |ext|
                ext.extension_data = "\x03\x04"
              end
            else
              raise ArgumentError, "Invalid on: #{on}"
            end
          end

          def extension_data=(data)
            super

            @protocol_versions = []
            buf = StringIO.new(data)
            case @on
            when :client_hello
              length = buf.read(1).unpack1("C") / 2
              length.times.map { @protocol_versions << buf.read(2) }
            when :server_hello
              @protocol_versions << buf.read(2)
            end
          end

          def serialize
            case @on
            when :client_hello
              data = [@protocol_versions.length * 2].pack("C") + @protocol_versions.join
              [EXTENSION_TYPE_NUMBER].pack("n") + [data.bytesize].pack("n") + data
            when :server_hello
              raise if @protocol_versions.length > 1

              data = @protocol_versions.join
              [EXTENSION_TYPE_NUMBER].pack("n") + [data.bytesize].pack("n") + data
            else
              # TODO: raise?
            end
          end
        end
      end
    end
  end
end
