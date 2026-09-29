# frozen_string_literal: true

require_relative "../codec"

module Raiha::Next::TLS
  module Extension
    # server_name (RFC 6066 §3).
    module ServerName
      TYPE = 0
      HOST_NAME = 0

      # In a ClientHello: a ServerNameList holding exactly one host_name, as
      # BoringSSL requires. RFC 6066 allows at most one name per type and
      # host_name is the only type defined.
      class CH < Data.define(:host_name)
        def self.parse(data)
          r = Codec::Reader.new(data)
          host_name = r.vector(2, min: 1, max: 0xffff) do |list|
            name_type = list.u8
            raise Codec::Malformed, "server_name: unknown name_type #{name_type}" unless name_type == HOST_NAME
            list.opaque(2, min: 1, max: 0xffff)
          end
          r.finish!
          new(host_name:)
        end

        def extension_type = TYPE

        def encode
          w = Codec::Writer.new
          w.vector(2, min: 1, max: 0xffff) do
            w.u8(HOST_NAME)
            w.vector(2, min: 1, max: 0xffff) { w.bytes(host_name) }
          end
          w.to_s
        end
      end

      # In EncryptedExtensions: empty, acknowledging the client's name.
      class EE < Data.define
        def self.parse(data)
          Codec::Reader.new(data).finish!
          new
        end

        def extension_type = TYPE

        def encode = "".b
      end
    end
  end
end
