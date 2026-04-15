# frozen_string_literal: true

require_relative "encryption_level"
require_relative "initial_aead"
require_relative "updatable_aead"
require_relative "transport_parameters"
require_relative "../protocol/perspective"
require_relative "../protocol/version"
require_relative "../protocol/connection_id"

module Raiha::Quic
  module Handshake
    # Manages QUIC packet protection across all encryption levels.
    # Coordinates Initial, Handshake, and 1-RTT AEAD instances
    # and provides encrypt/decrypt/header protection operations.
    #
    # @see https://www.rfc-editor.org/rfc/rfc9001.html
    class CryptoSetup
      attr_reader :perspective

      def initialize(perspective:, connection_id:, version: Protocol::Version::V1)
        @perspective = perspective
        @version = version
        @handshake_complete = false

        @initial_aead = InitialAEAD.new(
          connection_id: connection_id,
          perspective: perspective,
          version: version
        )

        @handshake_aead = nil
        @one_rtt_aead = nil

        @pending_crypto_data = {
          EncryptionLevel::INITIAL => String.new(encoding: "BINARY"),
          EncryptionLevel::HANDSHAKE => String.new(encoding: "BINARY"),
          EncryptionLevel::ONE_RTT => String.new(encoding: "BINARY"),
        }
      end

      def available?(level)
        aead_for_level(level)&.ready? || false
      end

      def handshake_complete?
        @handshake_complete
      end

      # Re-derive Initial AEAD keys from a new connection ID.
      # Used by the server when it receives the client's Initial packet
      # with a DCID that differs from the one used at construction.
      def rederive_initial_keys(connection_id:)
        @initial_aead = InitialAEAD.new(
          connection_id: connection_id,
          perspective: @perspective,
          version: @version
        )
      end

      # Set handshake keys derived from TLS key schedule
      def set_handshake_keys(client_secret:, server_secret:, cipher_suite:)
        @handshake_aead = UpdatableAEAD.new(
          client_secret: client_secret,
          server_secret: server_secret,
          perspective: @perspective,
          cipher_suite: cipher_suite
        )
      end

      # Set application (1-RTT) keys derived from TLS key schedule
      def set_application_keys(client_secret:, server_secret:, cipher_suite:)
        @one_rtt_aead = UpdatableAEAD.new(
          client_secret: client_secret,
          server_secret: server_secret,
          perspective: @perspective,
          cipher_suite: cipher_suite
        )
        @handshake_complete = true
      end

      # Encrypt a packet payload
      def encrypt(plaintext, packet_number:, aad:, level:)
        aead = aead_for_level(level)
        raise "Encryption not available for level #{level}" unless aead

        aead.encrypt(plaintext, packet_number: packet_number, aad: aad)
      end

      # Decrypt a packet payload
      def decrypt(ciphertext, packet_number:, aad:, level:)
        aead = aead_for_level(level)
        raise "Decryption not available for level #{level}" unless aead

        aead.decrypt(ciphertext, packet_number: packet_number, aad: aad)
      end

      # Get header protection mask for applying/removing header protection
      def header_protection_mask(sample, level:, direction: :send)
        aead = aead_for_level(level)
        raise "Header protection not available for level #{level}" unless aead

        aead.header_protection_mask(sample, direction: direction)
      end

      # Queue TLS handshake data to send at a specific encryption level
      def queue_crypto_data(data, level:)
        @pending_crypto_data[level] << data
      end

      # Get pending crypto data for a specific level
      def get_crypto_data(level:)
        data = @pending_crypto_data[level]
        @pending_crypto_data[level] = String.new(encoding: "BINARY")
        data.empty? ? nil : data
      end

      # Discard keys for a specific encryption level (after handshake progress)
      def discard_keys(level)
        case level
        when EncryptionLevel::INITIAL
          @initial_aead = nil
        when EncryptionLevel::HANDSHAKE
          @handshake_aead = nil
        end
      end

      # Rotate 1-RTT keys
      def update_keys
        raise "1-RTT keys not available" unless @one_rtt_aead

        @one_rtt_aead.rotate_keys
      end

      private def aead_for_level(level)
        case level
        when EncryptionLevel::INITIAL
          @initial_aead
        when EncryptionLevel::HANDSHAKE
          @handshake_aead
        when EncryptionLevel::ONE_RTT
          @one_rtt_aead
        end
      end
    end
  end
end
