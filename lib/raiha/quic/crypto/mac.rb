# frozen_string_literal: true

module Raiha::QUIC
  module Crypto
    # HMAC-SHA256, for the tokens an Endpoint makes and checks itself, and a
    # comparison of them that takes as long wherever they differ.
    module Mac
      LENGTH = 32

      def self.digest(key, data) = OpenSSL::HMAC.digest("SHA256", key, data)

      def self.same?(a, b) = a.bytesize == b.bytesize && OpenSSL.fixed_length_secure_compare(a, b)
    end
  end
end
