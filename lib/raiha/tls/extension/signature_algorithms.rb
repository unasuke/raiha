# frozen_string_literal: true

require_relative "../codec"

module Raiha::Next::TLS
  module Extension
    # signature_algorithms: `SignatureScheme supported_signature_algorithms<2..2^16-2>`.
    class SignatureAlgorithms < Data.define(:supported_signature_algorithms)
      TYPE = 13

      def self.parse(data)
        new(supported_signature_algorithms: parse_schemes(data))
      end

      # The SignatureSchemeList shared with signature_algorithms_cert.
      def self.parse_schemes(data)
        r = Codec::Reader.new(data)
        schemes = r.vector(2, min: 2, max: 0xfffe) do |v|
          # @type var list: Array[Integer]
          list = []
          list << v.u16 until v.eof?
          list.freeze
        end
        r.finish!
        schemes
      end

      def self.encode_schemes(schemes)
        w = Codec::Writer.new
        w.vector(2, min: 2, max: 0xfffe) { schemes.each { |scheme| w.u16(scheme) } }
        w.to_s
      end

      def extension_type = TYPE

      def encode = SignatureAlgorithms.encode_schemes(supported_signature_algorithms)
    end
  end
end
