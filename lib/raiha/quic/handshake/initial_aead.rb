# frozen_string_literal: true

require "openssl"
require_relative "../../crypto_util"
require_relative "../error"
require_relative "../protocol/perspective"
require_relative "../protocol/version"

module Raiha::Quic
  module Handshake
    # AEAD for Initial packets using AES-128-GCM
    # @see https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2
    class InitialAEAD
      ALGORITHM = "aes-128-gcm"
      KEY_LENGTH = 16
      IV_LENGTH = 12
      HP_KEY_LENGTH = 16
      TAG_LENGTH = 16

      # RFC 9001 Section 5.2 - Initial Salt for QUIC v1
      INITIAL_SALT_V1 = ["38762cf7f55934b34d179ae6a4c80cadccbb7f0a"].pack("H*").freeze
      # RFC 9369 - Initial Salt for QUIC v2
      INITIAL_SALT_V2 = ["0dede3def700a6db819381be6e269dcbf9bd2ed9"].pack("H*").freeze

      attr_reader :client_hp_key, :server_hp_key

      def initialize(connection_id:, perspective:, version: Protocol::Version::V1)
        @perspective = Protocol::Perspective.coerce(perspective)

        initial_salt = version == Protocol::Version::V2 ? INITIAL_SALT_V2 : INITIAL_SALT_V1
        initial_secret = OpenSSL::HMAC.digest("SHA256", initial_salt, connection_id.bytes)

        client_initial_secret = Raiha::CryptoUtil.hkdf_expand_label(initial_secret, "client in", "", 32)
        server_initial_secret = Raiha::CryptoUtil.hkdf_expand_label(initial_secret, "server in", "", 32)

        @client_key = Raiha::CryptoUtil.hkdf_expand_label(client_initial_secret, "quic key", "", KEY_LENGTH)
        @client_iv = Raiha::CryptoUtil.hkdf_expand_label(client_initial_secret, "quic iv", "", IV_LENGTH)
        @client_hp_key = Raiha::CryptoUtil.hkdf_expand_label(client_initial_secret, "quic hp", "", HP_KEY_LENGTH)

        @server_key = Raiha::CryptoUtil.hkdf_expand_label(server_initial_secret, "quic key", "", KEY_LENGTH)
        @server_iv = Raiha::CryptoUtil.hkdf_expand_label(server_initial_secret, "quic iv", "", IV_LENGTH)
        @server_hp_key = Raiha::CryptoUtil.hkdf_expand_label(server_initial_secret, "quic hp", "", HP_KEY_LENGTH)
      end

      def ready?
        true
      end

      def encrypt(plaintext, packet_number:, aad:)
        key, iv = send_key_iv
        nonce = compute_nonce(iv, packet_number)

        cipher = OpenSSL::Cipher.new(ALGORITHM)
        cipher.encrypt
        cipher.key = key
        cipher.iv = nonce
        cipher.auth_data = aad

        ciphertext = cipher.update(plaintext) + cipher.final
        ciphertext + cipher.auth_tag
      end

      def decrypt(ciphertext_with_tag, packet_number:, aad:)
        key, iv = receive_key_iv
        nonce = compute_nonce(iv, packet_number)

        tag = ciphertext_with_tag[-TAG_LENGTH..]
        ciphertext = ciphertext_with_tag[0...-TAG_LENGTH]

        cipher = OpenSSL::Cipher.new(ALGORITHM)
        cipher.decrypt
        cipher.key = key
        cipher.iv = nonce
        cipher.auth_data = aad
        cipher.auth_tag = tag

        cipher.update(ciphertext) + cipher.final
      end

      def header_protection_mask(sample, direction: :send)
        hp_key = direction == :send ? send_hp_key : receive_hp_key

        cipher = OpenSSL::Cipher.new("aes-128-ecb")
        cipher.encrypt
        cipher.key = hp_key
        cipher.padding = 0

        cipher.update(sample)[0, 5] or raise Raiha::Quic::Error, "TODO: header protection mask slice failed"
      end

      private def send_key_iv
        if @perspective.client?
          [@client_key, @client_iv]
        else
          [@server_key, @server_iv]
        end
      end

      private def receive_key_iv
        if @perspective.client?
          [@server_key, @server_iv]
        else
          [@client_key, @client_iv]
        end
      end

      private def send_hp_key
        @perspective.client? ? @client_hp_key : @server_hp_key
      end

      private def receive_hp_key
        @perspective.client? ? @server_hp_key : @client_hp_key
      end

      private def compute_nonce(iv, packet_number)
        nonce = iv.dup
        packet_number_bytes = [packet_number].pack("Q>")

        8.times do |i|
          nonce[IV_LENGTH - 8 + i] = (nonce[IV_LENGTH - 8 + i].ord ^ packet_number_bytes[i].ord).chr # steep:ignore
        end

        nonce
      end
    end
  end
end
