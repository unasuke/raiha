require_relative "abstract_extension"
require_relative "../../../util/io_reader"

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
            # RFC 8446 Section 4.3.1: server_name in EncryptedExtensions carries no data
            return if data.nil? || data.empty?

            buf = StringIO.new(data)
            _list_length = Raiha::Util::IOReader.read_exact(buf, 2).unpack1("n")
            name_type = Raiha::Util::IOReader.read_exact(buf, 1).unpack1("C")
            if name_type == 0 # host_name
              name_length = Raiha::Util::IOReader.read_exact(buf, 2).unpack1("n")
              @server_name = Raiha::Util::IOReader.read_exact(buf, name_length)
            end
          end

          def serialize
            if @server_name.nil? || @server_name.empty?
              # On EncryptedExtensions, the server_name is empty
              [EXTENSION_TYPE_NUMBER].pack("n") + [0].pack("n")
            else
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
end
