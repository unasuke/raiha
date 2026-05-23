# frozen_string_literal: true

require "openssl"
require_relative "../../crypto_util"
require_relative "../error"
require_relative "../protocol/perspective"

module Raiha::Quic
  module Handshake
    # AEAD with key update support for Handshake and 1-RTT packets
    # @see https://www.rfc-editor.org/rfc/rfc9001.html#section-5
    class UpdatableAEAD
      TAG_LENGTH = 16

      attr_reader :key_phase

      def initialize(client_secret:, server_secret:, perspective:, cipher_suite:)
        @perspective = Protocol::Perspective.coerce(perspective)
        @cipher_suite = cipher_suite
        @key_phase = false

        @algorithm = cipher_suite.aead_algorithm
        @hash_algorithm = cipher_suite.hash_algorithm
        @key_length = OpenSSL::Cipher.new(@algorithm).key_len
        @iv_length = 12

        @current_client_secret = client_secret
        @current_server_secret = server_secret

        derive_keys
      end

      def ready?
        true
      end

      def rotate_keys
        @current_client_secret = derive_next_secret(@current_client_secret)
        @current_server_secret = derive_next_secret(@current_server_secret)
        derive_keys
        @key_phase = !@key_phase
      end

      def encrypt(plaintext, packet_number:, aad:)
        key, iv = send_key_iv
        nonce = compute_nonce(iv, packet_number)

        cipher = OpenSSL::Cipher.new(@algorithm)
        cipher.encrypt
        cipher.key = key
        cipher.iv = nonce
        cipher.auth_data = aad

        ciphertext = cipher.update(plaintext) + cipher.final
        ciphertext + cipher.auth_tag
      end

      def decrypt(ciphertext_with_tag, packet_number:, aad:)
        key, iv = receive_key_iv
        do_decrypt(ciphertext_with_tag, packet_number: packet_number, aad: aad, key: key, iv: iv)
      end

      # Attempt decryption using the receive keys we would obtain AFTER a
      # key update (RFC 9001 §6.2). Used when an incoming short-header
      # packet advertises a Key Phase that differs from our current one:
      # if this call succeeds, the caller commits the key rotation via
      # rotate_keys. State is not mutated on either success or failure.
      def decrypt_next_phase(ciphertext_with_tag, packet_number:, aad:)
        next_client_secret = derive_next_secret(@current_client_secret)
        next_server_secret = derive_next_secret(@current_server_secret)
        next_receive_secret = @perspective.client? ? next_server_secret : next_client_secret

        key = Raiha::CryptoUtil.hkdf_expand_label(next_receive_secret, "quic key", "", @key_length, hash: @hash_algorithm)
        iv = Raiha::CryptoUtil.hkdf_expand_label(next_receive_secret, "quic iv", "", @iv_length, hash: @hash_algorithm)

        do_decrypt(ciphertext_with_tag, packet_number: packet_number, aad: aad, key: key, iv: iv)
      end

      private def do_decrypt(ciphertext_with_tag, packet_number:, aad:, key:, iv:)
        nonce = compute_nonce(iv, packet_number)

        tag = ciphertext_with_tag[-TAG_LENGTH..]
        ciphertext = ciphertext_with_tag[0...-TAG_LENGTH]

        cipher = OpenSSL::Cipher.new(@algorithm)
        cipher.decrypt
        cipher.key = key
        cipher.iv = nonce
        cipher.auth_data = aad
        cipher.auth_tag = tag

        cipher.update(ciphertext) + cipher.final
      end

      def header_protection_mask(sample, direction: :send)
        hp_key = direction == :send ? @send_hp : @receive_hp

        cipher = OpenSSL::Cipher.new(hp_cipher_name)
        cipher.encrypt
        cipher.key = hp_key
        cipher.padding = 0

        cipher.update(sample)[0, 5]
      end

      private def derive_keys
        @send_key = Raiha::CryptoUtil.hkdf_expand_label(send_secret, "quic key", "", @key_length, hash: @hash_algorithm)
        @send_iv = Raiha::CryptoUtil.hkdf_expand_label(send_secret, "quic iv", "", @iv_length, hash: @hash_algorithm)
        @send_hp = Raiha::CryptoUtil.hkdf_expand_label(send_secret, "quic hp", "", @key_length, hash: @hash_algorithm)

        @receive_key = Raiha::CryptoUtil.hkdf_expand_label(receive_secret, "quic key", "", @key_length, hash: @hash_algorithm)
        @receive_iv = Raiha::CryptoUtil.hkdf_expand_label(receive_secret, "quic iv", "", @iv_length, hash: @hash_algorithm)
        @receive_hp = Raiha::CryptoUtil.hkdf_expand_label(receive_secret, "quic hp", "", @key_length, hash: @hash_algorithm)
      end

      private def derive_next_secret(current_secret)
        digest_length = OpenSSL::Digest.new(@hash_algorithm).digest_length
        Raiha::CryptoUtil.hkdf_expand_label(current_secret, "quic ku", "", digest_length, hash: @hash_algorithm)
      end

      private def send_secret
        @perspective.client? ? @current_client_secret : @current_server_secret
      end

      private def receive_secret
        @perspective.client? ? @current_server_secret : @current_client_secret
      end

      private def send_key_iv
        [@send_key, @send_iv]
      end

      private def receive_key_iv
        [@receive_key, @receive_iv]
      end

      private def compute_nonce(iv, packet_number)
        nonce = iv.dup
        packet_number_bytes = [packet_number].pack("Q>")

        8.times do |i|
          nonce[@iv_length - 8 + i] = (nonce[@iv_length - 8 + i].ord ^ packet_number_bytes[i].ord).chr # steep:ignore
        end

        nonce
      end

      private def hp_cipher_name
        case @algorithm
        when "aes-128-gcm" then "aes-128-ecb"
        when "aes-256-gcm" then "aes-256-ecb"
        when "chacha20-poly1305" then "chacha20"
        else raise Raiha::Quic::Error, "Unsupported algorithm for header protection: #{@algorithm}"
        end
      end
    end
  end
end
