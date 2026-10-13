# frozen_string_literal: true

module Raiha::Next::QUIC
  module Crypto
    # The header protection of one key (RFC 9001 "Header Protection"): a
    # 5-byte mask from a 16-byte sample of the ciphertext. The AES-GCM suites
    # encrypt the sample with AES in ECB mode; ChaCha20-Poly1305 takes the
    # sample as the block counter and nonce of ChaCha20 and encrypts five
    # zero bytes. One OpenSSL context, keyed once.
    class HeaderProtection
      SAMPLE_LENGTH = 16
      MASK_LENGTH = 5
      CIPHERS = { aes_128_gcm: "aes-128-ecb", aes_256_gcm: "aes-256-ecb", chacha20_poly1305: "chacha20" }.freeze #: Hash[Symbol, String]
      ZEROS = ("\0".b * MASK_LENGTH).freeze

      def initialize(suite:, key:)
        raise ArgumentError, "#{suite.name} takes a #{suite.key_length}-byte header protection key" unless key.bytesize == suite.key_length
        @name = CIPHERS.fetch(suite.aead)
        @chacha20 = suite.aead == :chacha20_poly1305
        @cipher = OpenSSL::Cipher.new(@name)
        @cipher.encrypt
        @cipher.key = key
        @cipher.padding = 0 unless @chacha20
      end

      # The mask for `sample`, 5 bytes.
      def mask(sample) # steep:ignore
        raise ArgumentError, "a sample is #{SAMPLE_LENGTH} bytes, not #{sample.bytesize}" unless sample.bytesize == SAMPLE_LENGTH
        if @chacha20
          # OpenSSL's ChaCha20 takes a 16-byte IV, the 4-byte little-endian
          # block counter and then the 12-byte nonce: the sample as it is.
          @cipher.iv = sample
          @cipher.update(ZEROS)
        else
          @cipher.update(sample).byteslice(0, MASK_LENGTH)
        end
      end

      private def instance_variables_to_inspect = %i[@name]
    end
  end
end
