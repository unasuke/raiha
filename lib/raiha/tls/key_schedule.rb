# frozen_string_literal: true

require_relative "../crypto_util"
require_relative "cipher_suite"
require "openssl"

module Raiha
  module TLS
    # KeySchedule
    # @see https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
    class KeySchedule
      attr_accessor :public_key
      attr_accessor :pkey
      attr_accessor :group
      attr_reader :shared_secret
      attr_reader :client_handshake_traffic_secret
      attr_reader :server_handshake_traffic_secret
      attr_reader :client_application_traffic_secret
      attr_reader :server_application_traffic_secret

      def initialize(mode:)
        @mode = mode
        @shared_secret = nil
        @hash_algorithm = nil
        @aead_algorithm = nil
        @digest = nil
        @ikm = { early_secret: nil, handshake_secret: nil, main_secret: nil }
        @salt = { main_secret: nil }
        @client_application_traffic_secret = []
        @server_application_traffic_secret = []
      end

      def compute_shared_secret
        raise unless @group

        @shared_secret = case @group
        when "prime256v1", "secp384r1", "secp521r1"
          group = OpenSSL::PKey::EC::Group.new(@group)
          @pkey.dh_compute_key(OpenSSL::PKey::EC::Point.new(group, @public_key))
        when "x25519" # TODO: x448
          @pkey.derive(OpenSSL::PKey.new_raw_public_key("x25519", @public_key))
        else
          raise "TODO: #{@group} is not supported (yet)"
        end
      end

      def cipher_suite=(cipher_suite)
        @hash_algorithm = cipher_suite.hash_algorithm
        @aead_algorithm = cipher_suite.aead_algorithm
        @digest = OpenSSL::Digest.new(@hash_algorithm)
        @key_length = OpenSSL::Cipher.new(cipher_suite.aead_algorithm).key_len
        @iv_length = OpenSSL::Cipher.new(cipher_suite.aead_algorithm).iv_len
      end

      def derive_secret(secret:, label:, transcript_hash:)
        digest_length = OpenSSL::Digest.new(@hash_algorithm).digest_length
        case secret
        when :early_secret
          @ikm[:early_secret] = "\x00" * digest_length
          @ikm[:handshake_secret] = \
            OpenSSL::KDF.hkdf(@ikm[:early_secret], salt: "", info: hkdf_label(digest_length, label, transcript_hash), length: digest_length, hash: @hash_algorithm)
        when :handshake_secret
          raise unless @ikm[:handshake_secret] # TODO: nice error message
          raise unless @shared_secret # TODO: nice error message

          empty_digest = OpenSSL::Digest.new(@hash_algorithm).new.digest
          @salt[:main_secret] = \
            OpenSSL::KDF.hkdf(@shared_secret, salt: @ikm[:handshake_secret], info: hkdf_label(digest_length, "derived", empty_digest), length: digest_length, hash: @hash_algorithm)
          OpenSSL::KDF.hkdf(@shared_secret, salt: @ikm[:handshake_secret], info: hkdf_label(digest_length, label, transcript_hash), length: digest_length, hash: @hash_algorithm)
        when :main_secret
          @ikm[:main_secret] = "\x00" * digest_length
          OpenSSL::KDF.hkdf(@ikm[:main_secret], salt: @salt[:main_secret], info: hkdf_label(digest_length, label, transcript_hash), length: digest_length, hash: @hash_algorithm)
        end
      end

      def hkdf_label(length, label, context)
        [length].pack("n") + ["tls13 #{label}".length].pack("C") + "tls13 #{label}" + [context.length].pack("C") + context
      end

      # TODO: not tested yet
      # def client_early_traffic_secret(client_hello)
      #   @client_early_traffic_secret ||= derive_secret(secret: :early_secret, label: "c e traffic", messages: [client_hello.serialize])
      # end

      # TODO: not tested yet
      # def early_exporter_secret(client_hello)
      #   @early_exporter_secret ||= derive_secret(secret: :early_secret, label: "e exp master", messages: [client_hello.serialize])
      # end

      def derive_client_handshake_traffic_secret(transcript_hash)
        @client_handshake_traffic_secret = derive_secret(secret: :handshake_secret, label: "c hs traffic", transcript_hash: transcript_hash)
      end

      def derive_server_handshake_traffic_secret(transcript_hash)
        @server_handshake_traffic_secret = derive_secret(secret: :handshake_secret, label: "s hs traffic", transcript_hash: transcript_hash)
      end

      def server_handshake_write_key
        @server_handshake_write_key ||= hkdf_expand(prk: @server_handshake_traffic_secret, info: hkdf_label(@key_length, "key", ""), length: @key_length)
      end

      def server_handshake_write_iv
        @server_handshake_write_iv ||= hkdf_expand(prk: @server_handshake_traffic_secret, info: hkdf_label(@iv_length, "iv", ""), length: @iv_length)
      end

      def client_handshake_write_key
        @client_handshake_write_key ||= hkdf_expand(prk: @client_handshake_traffic_secret, info: hkdf_label(@key_length, "key", ""), length: @key_length)
      end

      def client_handshake_write_iv
        @client_handshake_write_iv ||= hkdf_expand(prk: @client_handshake_traffic_secret, info: hkdf_label(@iv_length, "iv", ""), length: @iv_length)
      end

      def derive_client_application_traffic_secret(transcript_hash)
        # TODO: generation
        @client_application_traffic_secret[0] = derive_secret(secret: :main_secret, label: "c ap traffic", transcript_hash: transcript_hash)
      end

      def derive_server_application_traffic_secret(transcript_hash)
        # TODO: generation
        @server_application_traffic_secret[0] = derive_secret(secret: :main_secret, label: "s ap traffic", transcript_hash: transcript_hash)
      end

      def client_application_write_key
        @client_application_write_key ||= hkdf_expand(prk: @client_application_traffic_secret.last, info: hkdf_label(@key_length, "key", ""), length: @key_length)
      end

      def client_application_write_iv
        @client_application_write_iv ||= hkdf_expand(prk: @client_application_traffic_secret.last, info: hkdf_label(@iv_length, "iv", ""), length: @iv_length)
      end

      def server_application_write_key
        @server_application_write_key ||= hkdf_expand(prk: @server_application_traffic_secret.last, info: hkdf_label(@key_length, "key", ""), length: @key_length)
      end

      def server_application_write_iv
        @server_application_write_iv ||= hkdf_expand(prk: @server_application_traffic_secret.last, info: hkdf_label(@iv_length, "iv", ""), length: @iv_length)
      end

      # TODO: not tested yet
      # def client_application_traffic_secret(messages, generation = 0)
      #   @client_application_traffic_secret[generation] ||= derive_secret(secret: :main_secret, label: "c ap traffic", messages: messages.map(&:serialize))
      # end

      # TODO: not tested yet
      # def server_application_traffic_secret(messages, generation = 0)
      #   @server_application_traffic_secret[generation] ||= derive_secret(secret: :main_secret, label: "s ap traffic", messages: messages.map(&:serialize))
      # end

      # TODO: not tested yet
      # def exporter_secret(messages)
      #   @exporter_secret ||= derive_secret(secret: :main_secret, label: "exp master", messages: messages.map(&:serialize))
      # end

      # TODO: not tested yet
      # def resumption_secret(messages)
      #   @resumption_secret ||= derive_secret(secret: :handshake_secret, label: "res master", messages: messages.map(&:serialize))
      # end

      def finished_verify_data(transcript_hash, from: :server)
        key = from == :server ? @server_handshake_traffic_secret : @client_handshake_traffic_secret
        finished_key = CryptoUtil.hkdf_expand_label(key, "finished", "", OpenSSL::Digest.new(@hash_algorithm).digest_length)
        OpenSSL::HMAC.digest(@hash_algorithm, finished_key, transcript_hash)
      end

      # @see https://www.rfc-editor.org/rfc/rfc5869#section-2.3
      private def hkdf_expand(prk:, info:, length:)
        digest = OpenSSL::Digest.new(@hash_algorithm)
        n = (length.to_f/digest.digest_length).ceil
        t = ''
        okm = ''
        n.times do |i|
          t = OpenSSL::HMAC.digest(@hash_algorithm, prk, t + info + [i+1].pack("C"))
          okm += t
        end
        okm[0...length]
      end
    end
  end
end
