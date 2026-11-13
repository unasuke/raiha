# frozen_string_literal: true

require_relative "../codec"

module Raiha::TLS
  module Extension
    # server_name (RFC 6066 §3).
    module ServerName
      TYPE = 0
      HOST_NAME = 0

      # In a ClientHello: a ServerNameList. RFC 6066 allows at most one name
      # of each type and leaves room for types other than host_name, the only
      # one defined. A name of another type is skipped, read like a HostName
      # (opaque<1..2^16-1>, the only layout defined); a second host_name is
      # malformed. `host_name` is nil when the list holds none, which counts
      # as no SNI.
      class CH < Data.define(:host_name)
        def self.parse(data)
          r = Codec::Reader.new(data)
          host_name = r.vector(2, min: 1, max: 0xffff) do |list|
            # @type var found: String?
            found = nil
            until list.eof?
              name_type = list.u8
              name = list.opaque(2, min: 1, max: 0xffff)
              next unless name_type == HOST_NAME
              raise Codec::Malformed, "server_name: more than one host_name" if found
              found = name
            end
            found
          end
          r.finish!
          new(host_name:)
        end

        def extension_type = TYPE

        def encode
          name = host_name or raise Codec::EncodeError, "server_name: no host_name to send"
          w = Codec::Writer.new
          w.vector(2, min: 1, max: 0xffff) do
            w.u8(HOST_NAME)
            w.vector(2, min: 1, max: 0xffff) { w.bytes(name) }
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
