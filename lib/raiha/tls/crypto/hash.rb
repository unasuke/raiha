# frozen_string_literal: true

module Raiha::Next::TLS
  module Crypto
    # The hash functions of TLS 1.3 cipher suites, named by Symbol.
    HASHES = { sha256: "SHA256", sha384: "SHA384" }.freeze #: Hash[Symbol, String]
    HASH_LENGTHS = { sha256: 32, sha384: 48 }.freeze #: Hash[Symbol, Integer]

    def self.hash_length(hash) = HASH_LENGTHS.fetch(hash) { raise ArgumentError, "unknown hash: #{hash.inspect}" }

    def self.digest_name(hash) = HASHES.fetch(hash) { raise ArgumentError, "unknown hash: #{hash.inspect}" }

    def self.hash(hash, data) = OpenSSL::Digest.digest(digest_name(hash), data)

    def self.hmac(hash:, key:, data:) = OpenSSL::HMAC.digest(digest_name(hash), key, data)

    # Compares two secrets of the same, public length in constant time.
    # Different lengths raise ArgumentError: the caller must have checked the
    # length already, and answering false would hide a missing length check.
    def self.fixed_length_secure_compare(a, b) = OpenSSL.fixed_length_secure_compare(a, b)
  end
end
