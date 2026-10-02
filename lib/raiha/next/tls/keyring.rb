# frozen_string_literal: true

require "securerandom"
require_relative "config"
require_relative "crypto"
require_relative "key_exchange"
require_relative "masked_inspect"
require_relative "verifier"

module Raiha::Next::TLS
  # What a handshake needs besides its Config and cannot share between
  # Ractors: certificates and private keys, the trust store, the random
  # source and the key exchange provider. Build one per Ractor or process,
  # not per connection; parsing happens here, once.
  #
  # A Keyring is frozen but not shareable, so sending one to another Ractor
  # raises instead of sharing key material by accident.
  class Keyring
    # A certificate chain, leaf first, and the leaf's private key, as given:
    # DER, or PEM, which is parsed the same way.
    class Identity < Data.define(:cert_der, :key_der)
      include MaskedInspect

      def masked_members = %i[key_der]
    end

    # An Identity once parsed: the chain as certificates and as DER for the
    # Certificate message, and the private key.
    class Credential < Data.define(:chain, :chain_der, :key)
      def leaf = chain.fetch(0)
    end

    def self.client(config:, identities: [], random: SecureRandom, key_exchange: KeyExchange::OpenSSL.new, verifier: nil)
      raise ArgumentError, "Keyring.client takes a client Config" unless config.client?
      new(config:, identities:, random:, key_exchange:, verifier:)
    end

    def self.server(config:, identities:, random: SecureRandom, key_exchange: KeyExchange::OpenSSL.new, verifier: nil)
      raise ArgumentError, "Keyring.server takes a server Config" unless config.server?
      new(config:, identities:, random:, key_exchange:, verifier:)
    end

    private_class_method :new

    attr_reader :config, :credentials, :key_exchange, :verifier

    def initialize(config:, identities:, random:, key_exchange:, verifier:)
      @config = config
      @credentials = identities.map { |identity| parse(identity) }.freeze
      if config.server? && @credentials.empty?
        raise ArgumentError, "a server needs at least one identity to authenticate with"
      end
      @random = random
      unsupported = config.groups - key_exchange.supported_groups
      unless unsupported.empty?
        raise ArgumentError, "the key exchange provider does not support #{unsupported.inspect}"
      end
      @key_exchange = key_exchange
      @verifier = verifier || default_verifier(config)
      freeze
    end

    def random_bytes(length) = @random.bytes(length)

    # False for Verifier::None, so the application can tell that the peer
    # was not authenticated.
    def peer_verified?
      case @verifier
      when Verifier::None then false
      else true
      end
    end

    private def instance_variables_to_inspect = %i[@config @verifier]

    private def parse(identity)
      raise ArgumentError, "identities must be Keyring::Identity values" unless identity.is_a?(Identity)
      unless identity.cert_der.is_a?(Array) && !identity.cert_der.empty?
        raise ArgumentError, "an identity needs a certificate chain, leaf first"
      end
      chain = identity.cert_der.map do |der|
        Crypto::Certificate.parse(der) || raise(ArgumentError, "an identity's certificate does not parse")
      end
      key = Crypto::Signature.private_key(identity.key_der) or raise ArgumentError, "an identity's private key does not parse"
      leaf = chain.fetch(0)
      raise ArgumentError, "an identity's private key does not match its certificate" unless leaf.check_private_key(key)
      Credential.new(chain: chain.freeze, chain_der: chain.map { |cert| cert.to_der.freeze }.freeze, key:)
    end

    # A Verifier::Default over the Config's trust anchors. With none, it
    # could accept nobody, which is a mistake to report now.
    private def default_verifier(config)
      authenticates_peer = config.client? || config.client_auth != :none
      if authenticates_peer && config.trust_anchors.empty?
        raise ArgumentError, "the default verifier needs trust_anchors in the Config (or pass verifier:)"
      end
      Verifier::Default.new(store: Verifier::Default.store(config.trust_anchors), verify_flags: config.verify_flags)
    end
  end
end
