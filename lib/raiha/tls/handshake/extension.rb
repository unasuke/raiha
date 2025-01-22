require "stringio"

module Raiha
  module TLS
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
          record_size_limit: 28,
          session_ticket: 35,
          pre_shared_key: 41,
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

        def self.deserialize_extensions(data, type:)
          extensions = []
          buf = StringIO.new(data)
          until buf.eof?
            ext_type = buf.read(2).unpack1("n")
            ext_data_length = buf.read(2).unpack1("n")
            ext_data = buf.read(ext_data_length)

            if (ext_type_name = EXTENSION_TYPE.invert[ext_type])
              extension = self.const_get(ext_type_name.to_s.split("_").map(&:capitalize).join).new(on: type)
              extension.extension_data = ext_data
            else
              extension = self.new
              extension.extension_type = ext_type
              extension.extension_data = ext_data
            end
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
end

%w[
  server_name
  max_fragment_length
  status_request
  supported_groups
  signature_algorithms
  use_srtp
  heartbeat
  application_layer_protocol_negotiation
  signed_certificate_timestamp
  client_certificate_type
  server_certificate_type
  padding
  record_size_limit
  session_ticket
  pre_shared_key
  early_data
  supported_versions
  cookie
  psk_key_exchange_modes
  certificate_authorities
  oid_filters
  post_handshake_auth
  signature_algorithms_cert
  key_share
].each do |file|
  require_relative "extension/#{file}"
end
