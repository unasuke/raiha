# frozen_string_literal: true

require_relative "../codec"

module Raiha::TLS
  module Extension
    # certificate_authorities:
    # `DistinguishedName authorities<3..2^16-1>` of `opaque DistinguishedName<1..2^16-1>`.
    class CertificateAuthorities < Data.define(:authorities)
      TYPE = 47

      def self.parse(data)
        r = Codec::Reader.new(data)
        names = r.vector(2, min: 3, max: 0xffff) do |v|
          # @type var list: Array[String]
          list = []
          list << v.opaque(2, min: 1, max: 0xffff) until v.eof?
          list.freeze
        end
        r.finish!
        new(authorities: names)
      end

      def extension_type = TYPE

      def encode
        w = Codec::Writer.new
        w.vector(2, min: 3, max: 0xffff) do
          authorities.each { |name| w.vector(2, min: 1, max: 0xffff) { w.bytes(name) } }
        end
        w.to_s
      end
    end
  end
end
