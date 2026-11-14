# frozen_string_literal: true

require_relative "../codec"

module Raiha::TLS
  module Extension
    # compress_certificate (RFC 8879 §3):
    # `CertificateCompressionAlgorithm algorithms<2..2^8-2>`.
    class CompressCertificate < Data.define(:algorithms)
      TYPE = 27

      def self.parse(data)
        r = Codec::Reader.new(data)
        algorithms = r.vector(1, min: 2, max: 0xfe) do |v|
          # @type var list: Array[Integer]
          list = []
          list << v.u16 until v.eof?
          list.freeze
        end
        r.finish!
        new(algorithms:)
      end

      def extension_type = TYPE

      def encode
        w = Codec::Writer.new
        w.vector(1, min: 2, max: 0xfe) { algorithms.each { |algorithm| w.u16(algorithm) } }
        w.to_s
      end
    end
  end
end
