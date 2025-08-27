require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # ServerName Extension
        #   struct {
        #       NameType name_type;
        #       select (name_type) {
        #           case host_name: HostName;
        #       } name;
        #   } ServerName;
        #
        #   enum {
        #       host_name(0), (255)
        #   } NameType;
        #
        #   opaque HostName<1..2^16-1>;
        #
        #   struct {
        #       ServerName server_name_list<1..2^16-1>
        #   } ServerNameList;
        #
        # @see https://datatracker.ietf.org/doc/html/rfc6066#section-3
        class ServerName < AbstractExtension
          EXTENSION_TYPE_NUMBER = 0
          attr_accessor :server_name

          def extension_data=(data)
            super
            @server_name = @extension_data
          end

          def serialize
            server_name = [0].pack("C") + # host_name(0)
              [@server_name.bytesize].pack("n") + @server_name # HostName
            server_name_list = [server_name.bytesize].pack("n") + server_name
            [EXTENSION_TYPE_NUMBER].pack("n") + [server_name_list.bytesize].pack("n") + server_name_list
          end
        end
      end
    end
  end
end
