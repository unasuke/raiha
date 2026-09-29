# frozen_string_literal: true

require_relative "../codec"

module Raiha::Next::TLS
  module Extension
    # supported_versions.
    module SupportedVersions
      TYPE = 43

      # In a ClientHello: `ProtocolVersion versions<2..254>`.
      class CH < Data.define(:versions)
        def self.parse(data)
          r = Codec::Reader.new(data)
          versions = r.vector(1, min: 2, max: 254) do |v|
            # @type var list: Array[Integer]
            list = []
            list << v.u16 until v.eof?
            list.freeze
          end
          r.finish!
          new(versions:)
        end

        def extension_type = TYPE

        def encode
          w = Codec::Writer.new
          w.vector(1, min: 2, max: 254) { versions.each { |version| w.u16(version) } }
          w.to_s
        end
      end

      # In a ServerHello or HelloRetryRequest: the one version selected.
      class SH < Data.define(:selected_version)
        def self.parse(data)
          r = Codec::Reader.new(data)
          version = r.u16
          r.finish!
          new(selected_version: version)
        end

        def extension_type = TYPE

        def encode
          w = Codec::Writer.new
          w.u16(selected_version)
          w.to_s
        end
      end
    end
  end
end
