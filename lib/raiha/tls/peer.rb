# frozen_string_literal: true

require_relative "../crypto_util"
require_relative "aead"
require_relative "application_data"
require_relative "record"

module Raiha
  module TLS
    # Shared behavior between TLS::Client and TLS::Server.
    #
    # Subclasses must supply these hooks:
    #   - #negotiated_cipher_suite : the selected CipherSuite instance
    #   - #own_cipher              : the AEAD used to encrypt outgoing records
    #   - #peer_cipher             : the AEAD used to decrypt incoming records
    class Peer
      attr_reader :state
      attr_reader :key_schedule
      attr_reader :server_hello
      attr_reader :transcript_hash
      attr_accessor :additional_extensions

      def negotiated_cipher_suite
        raise NotImplementedError, "#{self.class} must implement #negotiated_cipher_suite"
      end

      def own_cipher
        raise NotImplementedError, "#{self.class} must implement #own_cipher"
      end

      def peer_cipher
        raise NotImplementedError, "#{self.class} must implement #peer_cipher"
      end

      def encrypt_application_data(data)
        innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
          inner.content = ApplicationData.new.tap { |appdata| appdata.content = data }.serialize
          inner.content_type = Record::CONTENT_TYPE[:application_data]
        end
        own_cipher.encrypt(plaintext: innerplaintext, phase: :application).serialize
      end

      def receive_application_data
        loop do
          received = @received.shift
          break if received.nil?
          next if received.plaintext?

          inner_plaintext = peer_cipher.decrypt(ciphertext: received, phase: :application)
          inner_plaintext.content
        end
      end

      # Install handshake AEAD ciphers for both directions using the negotiated
      # cipher suite and the current key schedule.
      private def setup_cipher
        cipher_suite = negotiated_cipher_suite
        @server_cipher = AEAD.new(cipher_suite: cipher_suite, key_schedule: @key_schedule, mode: :server)
        @client_cipher = AEAD.new(cipher_suite: cipher_suite, key_schedule: @key_schedule, mode: :client)
      end
      # RFC 8446 Section 7.1: derive client/server application traffic secrets
      # from the current master secret and transcript hash.
      private def derive_application_traffic_secrets
        @key_schedule.derive_client_application_traffic_secret(@transcript_hash.hash)
        @key_schedule.derive_server_application_traffic_secret(@transcript_hash.hash)
      end

      # RFC 8446 Section 4.2.11.2: compute the PSK binder over a truncated
      # ClientHello. Both sides run the exact same computation (client to
      # populate the binder, server to verify it).
      private def compute_psk_binder(psk, truncated_client_hello, hash_alg)
        digest_length = OpenSSL::Digest.new(hash_alg).digest_length

        early_secret = OpenSSL::HMAC.digest(hash_alg, "\x00" * digest_length, psk)
        empty_hash = OpenSSL::Digest.new(hash_alg).digest
        binder_key = CryptoUtil.hkdf_expand_label(early_secret, "res binder", empty_hash, digest_length, hash: hash_alg)
        finished_key = CryptoUtil.hkdf_expand_label(binder_key, "finished", "", digest_length, hash: hash_alg)

        transcript_hash = OpenSSL::Digest.new(hash_alg).digest(truncated_client_hello)
        OpenSSL::HMAC.digest(hash_alg, finished_key, transcript_hash)
      end
    end
  end
end
