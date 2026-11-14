# frozen_string_literal: true

module Raiha::TLS
  module Crypto
    # One key of an AEAD algorithm of the TLS 1.3 cipher suites (RFC 5116),
    # named by Symbol. Each direction keeps its own OpenSSL context, keyed
    # once and given a fresh nonce for every call.
    #
    # A failed authentication is nil, not an exception: the bytes come from
    # the peer, and the record layer turns nil into bad_record_mac.
    class AEAD
      CIPHERS = { aes_128_gcm: "aes-128-gcm", aes_256_gcm: "aes-256-gcm", chacha20_poly1305: "chacha20-poly1305" }.freeze #: Hash[Symbol, String]
      TAG_LENGTH = 16

      def initialize(algorithm, key)
        @name = CIPHERS.fetch(algorithm) { raise ArgumentError, "unknown AEAD: #{algorithm.inspect}" }
        @key = key.b
        @sealer = nil #: OpenSSL::Cipher?
        @opener = nil #: OpenSSL::Cipher?
      end

      # The ciphertext followed by the tag.
      def seal(nonce:, aad:, plaintext:)
        cipher = @sealer ||= context(:encrypt)
        cipher.iv = nonce
        cipher.auth_data = aad
        sealed = plaintext.empty? ? "".b : cipher.update(plaintext)
        sealed << cipher.final << cipher.auth_tag(TAG_LENGTH)
      end

      # The plaintext, or nil when `ciphertext` (with its tag) does not
      # authenticate under `nonce` and `aad`.
      def open(nonce:, aad:, ciphertext:)
        return nil if ciphertext.bytesize < TAG_LENGTH
        cipher = @opener ||= context(:decrypt)
        body_length = ciphertext.bytesize - TAG_LENGTH
        cipher.iv = nonce
        cipher.auth_tag = ciphertext.byteslice(body_length, TAG_LENGTH).to_s
        cipher.auth_data = aad
        opened = body_length.zero? ? "".b : cipher.update(ciphertext.byteslice(0, body_length).to_s)
        opened << cipher.final
      rescue OpenSSL::Cipher::CipherError
        nil
      end

      # Forgets the key, a best effort: OpenSSL's contexts keep their own
      # copies until collected.
      def discard!
        @key.clear
        @sealer = nil
        @opener = nil
      end

      private def instance_variables_to_inspect = %i[@name]

      private def context(direction)
        cipher = OpenSSL::Cipher.new(@name)
        direction == :encrypt ? cipher.encrypt : cipher.decrypt
        cipher.key = @key
        cipher
      end
    end
  end
end
