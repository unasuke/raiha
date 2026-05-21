require_relative "cipher_suite"

module Raiha
  module TLS
    class Config
      DEFAULT_CIPHER_SUITES = [
        CipherSuite.new(:TLS_AES_256_GCM_SHA384),
        CipherSuite.new(:TLS_AES_128_GCM_SHA256),
        CipherSuite.new(:TLS_CHACHA20_POLY1305_SHA256),
      ].freeze

      DEFAULT_SUPPORTED_GROUPS = [
        "prime256v1",
      ].freeze

      attr_reader :cipher_suites
      attr_reader :supported_groups
      attr_accessor :server_certificate
      attr_accessor :server_private_key
      attr_accessor :client_certificate
      attr_accessor :client_private_key
      attr_accessor :client_ca_store
      attr_accessor :request_client_certificate
      attr_accessor :transcript_hash_verify

      def self.client_default
        self.new(
          cipher_suites: DEFAULT_CIPHER_SUITES,
          supported_groups: DEFAULT_SUPPORTED_GROUPS,
          transcript_hash_verify: ENV["RAIHA_TRANSCRIPT_VERIFY"] == "1",
        )
      end

      def self.server_default
        self.new(
          cipher_suites: DEFAULT_CIPHER_SUITES,
          supported_groups: DEFAULT_SUPPORTED_GROUPS,
          transcript_hash_verify: ENV["RAIHA_TRANSCRIPT_VERIFY"] == "1",
        )
      end

      def initialize(cipher_suites:, supported_groups:, transcript_hash_verify: false)
        @cipher_suites = cipher_suites
        @supported_groups = supported_groups
        @transcript_hash_verify = transcript_hash_verify
      end
    end
  end
end
