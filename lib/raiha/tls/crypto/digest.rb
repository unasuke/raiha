# frozen_string_literal: true

require_relative "hash"

module Raiha::TLS
  module Crypto
    # A running hash. `#digest` returns the hash of everything added so far
    # and keeps accumulating.
    class Digest
      attr_reader :hash_name

      def initialize(hash_name)
        @hash_name = hash_name
        @digest = OpenSSL::Digest.new(Crypto.digest_name(hash_name))
      end

      def <<(bytes)
        @digest << bytes
        self
      end

      def digest = @digest.digest

      def initialize_copy(other)
        super
        @digest = @digest.dup
      end
    end
  end
end
