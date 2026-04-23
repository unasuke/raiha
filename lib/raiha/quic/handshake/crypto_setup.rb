# frozen_string_literal: true

require_relative "encryption_level"
require_relative "initial_aead"
require_relative "updatable_aead"
require_relative "transport_parameters"
require_relative "../error"
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
        @perspective = Protocol::Perspective.coerce(perspective)
        @version = version
        @handshake_complete = false

        @initial_aead = InitialAEAD.new(
          connection_id: connection_id,
          perspective: perspective,
          version: version
        )

        @handshake_aead = nil
        @one_rtt_aead = nil

        # Per-level queue of pending outgoing CRYPTO frame payloads, each
        # tagged with the offset at which it must be placed in the TLS
        # stream (RFC 9000 §19.6). Entries are dequeued by get_crypto_data
        # and re-enqueued verbatim when a carrying packet is declared lost.
        @pending_crypto_data = {
          EncryptionLevel::INITIAL => [],
          EncryptionLevel::HANDSHAKE => [],
          EncryptionLevel::ONE_RTT => [],
        } #: Hash[Symbol, Array[{offset: Integer, data: String}]]
        # Running offset cursor per level: next contiguous TLS-stream byte
        # index a fresh queue_crypto_data call will claim.
        @next_crypto_offset = {
          EncryptionLevel::INITIAL => 0,
          EncryptionLevel::HANDSHAKE => 0,
          EncryptionLevel::ONE_RTT => 0,
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
        raise Raiha::Quic::Error, "Encryption not available for level #{level}" unless aead

        aead.encrypt(plaintext, packet_number: packet_number, aad: aad)
      end

      # Decrypt a packet payload
      def decrypt(ciphertext, packet_number:, aad:, level:)
        aead = aead_for_level(level)
        raise Raiha::Quic::Error, "Decryption not available for level #{level}" unless aead

        aead.decrypt(ciphertext, packet_number: packet_number, aad: aad)
      end

      # Get header protection mask for applying/removing header protection
      def header_protection_mask(sample, level:, direction: :send)
        aead = aead_for_level(level)
        raise Raiha::Quic::Error, "Header protection not available for level #{level}" unless aead

        aead.header_protection_mask(sample, direction: direction)
      end

      # Queue TLS handshake data to send at a specific encryption level
      def queue_crypto_data(data, level:)
        offset = @next_crypto_offset[level]
        @pending_crypto_data[level] << { offset: offset, data: data }
        @next_crypto_offset[level] = offset + data.bytesize
      end

      # Drain every pending CRYPTO chunk for the level and return the bytes
      # as a single concatenated String. Preserved for callers that treat
      # the queue as an opaque byte stream (tests, simple handshake
      # drivers). Returns nil when no data is pending.
      def get_crypto_data(level:)
        chunks = @pending_crypto_data[level]
        return nil if chunks.empty?

        data = chunks.map { |c| c[:data] }.join.b
        chunks.clear
        data
      end

      # Pop the oldest pending CRYPTO chunk for the level, preserving the
      # offset it was assigned when queued. Used by Connection to build
      # one CRYPTO frame per chunk so offsets land correctly on the wire
      # (RFC 9000 §19.6).
      def pop_crypto_frame(level:)
        @pending_crypto_data[level].shift
      end

      # Re-enqueue a CRYPTO payload at its original offset so it rides the
      # next flush. Used when the packet carrying it is declared lost
      # (RFC 9002 §6.3.1). The entry keeps its offset so the peer sees a
      # contiguous CRYPTO stream even across retransmissions.
      def requeue_crypto_data(offset:, data:, level:)
        @pending_crypto_data[level] << { offset: offset, data: data }
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

      # Trial-decrypt a 1-RTT packet with the next key phase's keys
      # (RFC 9001 §6.2). Returns the plaintext without mutating state;
      # raises OpenSSL::Cipher::CipherError on failure. Only defined for
      # the 1-RTT level because earlier levels don't support key update.
      def decrypt_next_phase(ciphertext, packet_number:, aad:)
        raise Raiha::Quic::Error, "1-RTT keys not available" unless @one_rtt_aead

        @one_rtt_aead.decrypt_next_phase(ciphertext, packet_number: packet_number, aad: aad)
      end

      # Rotate 1-RTT keys
      def update_keys
        raise Raiha::Quic::Error, "1-RTT keys not available" unless @one_rtt_aead

        @one_rtt_aead.rotate_keys
      end

      # Current 1-RTT Key Phase bit (RFC 9001 §6). Returns false when
      # 1-RTT is not yet established.
      def one_rtt_key_phase
        @one_rtt_aead&.key_phase || false
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
