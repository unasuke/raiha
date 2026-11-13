# frozen_string_literal: true

require_relative "signature_algorithms"

module Raiha::TLS
  module Extension
    # signature_algorithms_cert: the same SignatureSchemeList as
    # signature_algorithms, for signatures in certificates.
    class SignatureAlgorithmsCert < Data.define(:supported_signature_algorithms)
      TYPE = 50

      def self.parse(data)
        new(supported_signature_algorithms: SignatureAlgorithms.parse_schemes(data))
      end

      def extension_type = TYPE

      def encode = SignatureAlgorithms.encode_schemes(supported_signature_algorithms)
    end
  end
end
