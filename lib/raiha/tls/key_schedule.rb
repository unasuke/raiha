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

      def initialize(mode:)
        @mode = mode
        @shared_secret = nil
        @hash_algorithm = nil
        @aead_algorithm = nil
        @digest = nil
        @ikm = { early_secret: nil, handshake_secret: nil, main_secret: nil }
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
      end

      def derive_secret(secret:, label:, messages: [])
        digest_length = OpenSSL::Digest.new(@hash_algorithm).digest_length
        case secret
        when :early_secret
          @ikm[:early_secret] = "\x00" * digest_length
          @ikm[:handshake_secret] = \
            OpenSSL::KDF.hkdf(@ikm[:early_secret], salt: "", info: hkdf_label(digest_length, label, transcript_hash(messages)), length: digest_length, hash: @hash_algorithm)
        when :handshake_secret
          raise unless @ikm[:handshake_secret] # TODO: nice error message
          raise unless @shared_secret # TODO: nice error message

          OpenSSL::KDF.hkdf(@shared_secret, salt: @ikm[:handshake_secret], info: hkdf_label(digest_length, label, transcript_hash(messages)), length: digest_length, hash: @hash_algorithm)
        when :main_secret
          # TODO
        end
      end

      def hkdf_label(length, label, context)
        [length].pack("n") + ["tls13 #{label}".length].pack("C") + "tls13 #{label}" + [context.length].pack("C") + context
      end

      def transcript_hash(messages = [])
        raise unless @hash_algorithm
        hash = OpenSSL::Digest.new(@hash_algorithm).new
        # messages.each do |message|
        hash.update(messages.join)
        hash.digest
      end


      # TODO: not tested yet
      # def client_early_traffic_secret(client_hello)
      #   @client_early_traffic_secret ||= derive_secret(secret: :early_secret, label: "c e traffic", messages: [client_hello.serialize])
      # end

      # TODO: not tested yet
      # def early_exporter_secret(client_hello)
      #   @early_exporter_secret ||= derive_secret(secret: :early_secret, label: "e exp master", messages: [client_hello.serialize])
      # end

      def client_handshake_traffic_secret(messages)
        @client_handshake_traffic_secret ||= derive_secret(secret: :handshake_secret, label: "c hs traffic", messages: messages.map(&:serialize))
      end

      def server_handshake_traffic_secret(messages)
        @server_handshake_traffic_secret ||= derive_secret(secret: :handshake_secret, label: "s hs traffic", messages: messages.map(&:serialize))
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
    end
  end
end
