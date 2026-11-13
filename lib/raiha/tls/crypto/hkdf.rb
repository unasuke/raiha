# frozen_string_literal: true

require_relative "hash"

module Raiha::TLS
  module Crypto
    # HKDF (RFC 5869), split into its two steps as TLS 1.3 uses them.
    module HKDF
      def self.extract(hash:, salt:, ikm:)
        Crypto.hmac(hash:, key: salt, data: ikm)
      end

      def self.expand(hash:, prk:, info:, length:)
        hash_length = Crypto.hash_length(hash)
        raise ArgumentError, "HKDF-Expand length #{length} is out of range" unless length.between?(0, 255 * hash_length)
        output = String.new(encoding: Encoding::BINARY)
        block = "".b
        counter = 1
        while output.bytesize < length
          block = Crypto.hmac(hash:, key: prk, data: block + info + counter.chr)
          output << block
          counter += 1
        end
        output.byteslice(0, length) #: String
      end
    end
  end
end
