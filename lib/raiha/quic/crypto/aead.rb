# frozen_string_literal: true

require "openssl"
require "raiha/quic/crypto"

module Raiha::Quic
  module Crypto
    # Provide AEAD function (wraps OpenSSL) for QUIC
    # @see https://www.rfc-editor.org/rfc/rfc5116.html
    # @see https://www.rfc-editor.org/rfc/rfc9001.html#name-aead-usage
    class AEAD
      # AEAD nonce length (AEAD_AES_128_GCM)
      # @see https://www.rfc-editor.org/rfc/rfc5116.html#section-5.1
      NONCE_LENGTH = 12

      # AEAD tag length (AEAD_AES_128_GCM)
      # @see https://www.rfc-editor.org/rfc/rfc5116.html#section-5.1
      TAG_LENGTH = 16

      # @param cipher_name [String] cipher name. Valid values are
      #   acceptable for +OpenSSL::Cipher.new+
      # @param key [String] The key for encryption or decryption. Same as key (secret key) in RFC 5116
      # @param iv [String] The initialization vector for encrypton or decryption. It uses for a part as a nonce.
      def initialize(ciper_name, key, iv)
        @cipher_name = ciper_name
        @key = key
        @iv = iv
      end

      # Encrypt given data by given cipher.
      # @param data [String] The target data of encrypt. Same as P (plaintext) in RFC 5116
      # @param associated_data [String] Associated data. Same as A (associated data) in RFC 5116
      # @param packet_number [Integer] The packet number.
      # @return [String] The encrypted string. Same as C (ciphertext) in RFC 5116
      def encrypt(data, associated_data, packet_number)
        cipher = OpenSSL::Cipher.new(@cipher_name)
        nonce = @iv.dup
        8.times do |i|
          nonce[NONCE_LENGTH - 1 - i] = IO::Buffer.for(nonce[NONCE_LENGTH-i-1]).dup.xor!(IO::Buffer.for([packet_number >> (8*i)].pack("C*"))).get_string
        end
        cipher.encrypt
        cipher.key = @key
        cipher.iv = nonce
        cipher.auth_data = associated_data
        encrypted = cipher.update(data) + cipher.final
        return encrypted + cipher.auth_tag
      end

      # Decrypt given data by given cipher.
      # @param data [String] The encrypted data. Same as C (plaintext) in RFC 5116
      # @param associated_data [String] Associated data. Same as A (associated data) in RFC 5116
      # @param packet_number [Integer] The packet number.
      # @return [String] The decrypted string. Same as P (plaintext) in RFC 5116
      def decrypt(data, associated_data, packet_number)
        cipher = OpenSSL::Cipher.new(@cipher_name)
        nonce = @iv.dup
        8.times do |i|
          nonce[NONCE_LENGTH - 1 - i] = IO::Buffer.for(nonce[NONCE_LENGTH-i-1]).dup.xor!(IO::Buffer.for([packet_number >> (8*i)].pack("C*"))).get_string
        end
        cipher.decrypt
        cipher.key = @key
        cipher.iv = nonce
        cipher.auth_tag = data.slice(data.length - TAG_LENGTH, TAG_LENGTH)
        cipher.auth_data = associated_data
        decrypted = cipher.update(data.slice(0...(data.length-TAG_LENGTH))) + cipher.final
        return decrypted
      end
    end
  end
end
