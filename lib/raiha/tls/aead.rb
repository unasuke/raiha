require "openssl"

require_relative "key_schedule"
require_relative "cipher_suite"
require_relative "record"

module Raiha
  module TLS
    class AEAD
      attr_accessor :mode

      def initialize(cipher_suite:, key_schedule:, mode: :server)
        @cipher_suite = cipher_suite
        @sequence_number = 0
        @cipher = OpenSSL::Cipher.new(cipher_suite.aead_algorithm)
        @key_schedule = key_schedule
        @mode = mode # TODO: mode useful api
      end

      def decrypt(ciphertext:, phase:)
        key, iv = key_and_iv_from_phase(phase)
        @cipher.reset
        @cipher.decrypt
        @cipher.key = key
        @cipher.iv = nonce(iv)
        @cipher.auth_data = ciphertext.additional_data
        @cipher.auth_tag = ciphertext.auth_tag

        Record::TLSInnerPlaintext.deserialize(
          @cipher.update(ciphertext.encrypted_record_without_auth_tag) + @cipher.final
        ).tap { @sequence_number += 1 }
      end

      def encrypt(plaintext:, phase:)
        key, iv = key_and_iv_from_phase(phase)
        @cipher.reset
        @cipher.encrypt
        @cipher.key = key
        @cipher.iv = nonce(iv)
        @cipher.auth_data = plaintext.additional_data
        ciphertext = @cipher.update(plaintext.serialize) + @cipher.final + @cipher.auth_tag

        Record::TLSCiphertext.new.tap do |ct|
          ct.encrypted_record = ciphertext
          ct.tls_inner_plaintext = plaintext
        end.tap { @sequence_number += 1 }
      end

      # TODO: more useful api
      def reset_sequence_number
        @sequence_number = 0
      end

      private def key_and_iv_from_phase(phase)
        case @mode
        when :server
          key_and_iv_server(phase)
        when :client
          key_and_iv_client(phase)
        end
      end

      private def key_and_iv_server(phase)
        case phase
        when :handshake
          [
            @key_schedule.server_handshake_write_key,
            @key_schedule.server_handshake_write_iv,
          ]
        when :application
          [
            @key_schedule.server_application_write_key,
            @key_schedule.server_application_write_iv,
          ]
        end
      end

      private def key_and_iv_client(phase)
        case phase
        when :handshake
          [
            @key_schedule.client_handshake_write_key,
            @key_schedule.client_handshake_write_iv,
          ]
        when :application
          [
            @key_schedule.client_application_write_key,
            @key_schedule.client_application_write_iv,
          ]
        end
      end

      private def nonce(key)
        sequence_number_in_8_octets = [@sequence_number].pack("Q>").unpack("C*")
        (@cipher.iv_len - sequence_number_in_8_octets.length).times do
          sequence_number_in_8_octets.unshift(0)
        end
        sequence_number_in_8_octets.zip(key.unpack("C*")).map { |a, b| a ^ b }.pack("C*")
      end
    end
  end
end
