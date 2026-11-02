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

    # The subjects of the Config's trust anchors, as DER, for the
    # certificate_authorities extension of a CertificateRequest.
    attr_reader :trust_anchor_subjects

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
      @trust_anchor_subjects = config.trust_anchors.map do |der|
        anchor = Crypto::Certificate.parse(der) or raise ArgumentError, "a trust anchor is not a DER certificate"
        anchor.subject.to_der.freeze
      end.freeze
      freeze
    end

    # Where the connection's random bytes come from, for a QUIC connection
    # as well as for TLS, so that a seeded one makes a test repeatable.
    attr_reader :random

    # A Keyring of this one's Config with `ticket_keys` in place of its
    # own: the certificates, keys, verifier and random source are this
    # one's, not parsed again. A server that turns a TicketKeys.ratchet
    # over builds a Config for each epoch, and a handshake takes only the
    # Keyring of its own Config.
    def with_ticket_keys(ticket_keys) = dup.bind(@config.with(ticket_keys:))

    # A copy made by `with_ticket_keys` takes its Config.
    protected def bind(config)
      @config = config
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

    # The client's answer to a CertificateRequest (RFC 9846 "Certificate
    # Selection"): the first identity whose key signs with a scheme the
    # server lists, and, when the server names CAs, whose chain has an issuer
    # among them; with the scheme, in our order of preference. nil when none
    # fits, and the client then sends an empty Certificate.
    def client_credential(signature_algorithms:, certificate_authorities:)
      @credentials.each do |credential|
        scheme = scheme_for(credential, signature_algorithms) or next
        if certificate_authorities && credential.chain.none? { |cert| certificate_authorities.include?(cert.issuer.to_der) }
          next
        end
        return [credential, scheme]
      end
      nil
    end

    # The server's certificate when no PSK was selected. Candidates are the
    # identities whose key signs with a scheme the client lists; among them
    # the best by, in order: valid for `server_name` (RFC 9525), every
    # signature in the chain acceptable to the client, an issuer among the
    # client's certificate_authorities. Ties go to the order of the
    # identities, and with no candidate at all the result is nil.
    def server_credential(server_name:, signature_algorithms:, signature_algorithms_cert:, certificate_authorities:)
      chain_schemes = signature_algorithms_cert || signature_algorithms
      candidates = @credentials.filter_map.with_index do |credential, index|
        scheme = scheme_for(credential, signature_algorithms) or next
        rank = [
          server_name && Verifier::HostName.match?(credential.leaf, server_name) ? 0 : 1,
          chain_signatures_acceptable?(credential, chain_schemes) ? 0 : 1,
          certificate_authorities && credential.chain.any? { |cert| certificate_authorities.include?(cert.issuer.to_der) } ? 0 : 1,
          index
        ]
        [rank, credential, scheme]
      end
      best = candidates.min_by(&:first) or return nil
      [best[1], best[2]]
    end

    # Our preferred scheme the credential's key signs with, among `offered`.
    private def scheme_for(credential, offered)
      @config.signature_algorithms.each do |name|
        scheme = Config::SCHEMES_BY_NAME.fetch(name)
        return scheme if offered.include?(scheme.id) && Crypto::Signature.key_matches?(scheme, credential.key)
      end
      nil
    end

    # Every signature in the chain but a self-signed one's is one of
    # `schemes`.
    private def chain_signatures_acceptable?(credential, schemes)
      credential.chain.all? do |cert|
        cert.subject.to_der == cert.issuer.to_der || schemes.include?(Crypto::Certificate.signature_scheme_id(cert))
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
