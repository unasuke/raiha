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
      attr_reader :server_certificate
      attr_reader :server_private_key

      def self.client_default
        self.new(
          cipher_suites: DEFAULT_CIPHER_SUITES,
          supported_groups: DEFAULT_SUPPORTED_GROUPS,
        )
      end

      def self.server_default
      end

      def initialize(cipher_suites:, supported_groups:)
        @cipher_suites = cipher_suites
        @supported_groups = supported_groups
      end
    end
  end
end
