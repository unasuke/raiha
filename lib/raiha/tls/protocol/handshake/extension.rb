require "stringio"
require_relative "../handshake"

module Raiha::TLS::Protocol
  class Handshake
    class Extension
      EXTENSION_TYPE = {
        server_name: 0,
        max_fragment_length: 1,
        status_request: 5,
        supported_groups: 10,
        signature_algorithms: 13,
        use_srtp: 14,
        heartbeat: 15,
        application_layer_protocol_negotiation: 16,
        signed_certificate_timestamp: 18,
        client_certificate_type: 19,
        server_certificate_type: 20,
        padding: 21,
        pre_shred_key: 41,
        early_data: 42,
        supported_versions: 43,
        cookie: 44,
        psk_key_exchange_modes: 45,
        certificate_authorities: 47,
        oid_filters: 48,
        post_handshake_auth: 49,
        signature_algorithms_cert: 50,
        key_share: 51
      }.freeze

      attr_accessor :extension_type
      attr_accessor :extension_data

      def serialize
        packed_extension_data = extension_data.pack("C*")
        [extension_type].pack("n") + [packed_extension_data.bytesize].pack("n") + packed_extension_data
      end

      def self.deserialize_extensions(data)
        extensions = []
        buf = StringIO.new(data)
        until buf.eof?
          extension = self.new
          extension.extension_type = buf.read(2).unpack1("n")
          extension_data_length = buf.read(2).unpack1("n")
          extension.extension_data = buf.read(extension_data_length)
          extensions << extension
        end
        extensions
      end

      # def inspect
      #   readable_extension_type = EXTENSION_TYPE.invert[extension_type] || "unknown(#{extension_type})"
      #   "<#{self.class.name} @extension_type=#{readable_extension_type} @extension_data=#{extension_data.unpack1("H*").scan(/../).join(" ")}>"
      # end
    end
  end
end
