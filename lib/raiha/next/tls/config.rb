# frozen_string_literal: true

require_relative "iana"
require_relative "cipher_suite"
require_relative "signature_scheme"
require_relative "profile"
require_relative "extension"

module Raiha::Next::TLS
  # The settings a handshake runs with, shared by every connection and every
  # Ractor: a Config is deeply frozen and Ractor-shareable from the moment it
  # is built. Key material, the random source and anything else that cannot
  # be shared lives in a Keyring instead.
  #
  # Enumerated settings are given as Symbols and checked against what this
  # implementation knows. A setting that cannot work raises ArgumentError
  # here rather than failing a handshake later.
  class Config
    DEFAULT_CIPHER_SUITES = %i[TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256].freeze

    DEFAULT_GROUPS = %i[x25519 secp256r1 secp384r1].freeze

    # Schemes for a CertificateVerify, in our order of preference.
    DEFAULT_SIGNATURE_ALGORITHMS = %i[
      ecdsa_secp256r1_sha256 rsa_pss_rsae_sha256 ed25519
      ecdsa_secp384r1_sha384 rsa_pss_rsae_sha384 rsa_pss_rsae_sha512
    ].freeze

    # Schemes accepted in certificate chains, sent as signature_algorithms_cert.
    # RSASSA-PKCS1-v1_5 still signs most of the Web PKI.
    DEFAULT_SIGNATURE_ALGORITHMS_CERT = (DEFAULT_SIGNATURE_ALGORITHMS + %i[
      ecdsa_secp521r1_sha512 rsa_pkcs1_sha256 rsa_pkcs1_sha384 rsa_pkcs1_sha512
    ]).freeze

    # Extensions the state machine builds, or builds from a typed setting
    # here. Each extension has exactly one way to be set, so these cannot be
    # given in `extensions:`.
    RESERVED_EXTENSIONS = [
      Extension::SupportedVersions::TYPE, Extension::KeyShare::TYPE, Extension::SupportedGroups::TYPE,
      Extension::SignatureAlgorithms::TYPE, Extension::SignatureAlgorithmsCert::TYPE,
      Extension::PskKeyExchangeModes::TYPE, Extension::PreSharedKey::TYPE, Extension::EarlyData::TYPE,
      Extension::Cookie::TYPE,
      Extension::ServerName::TYPE, Extension::Alpn::TYPE, Extension::RecordSizeLimit::TYPE,
      Extension::CompressCertificate::TYPE, Extension::PostHandshakeAuth::TYPE
    ].freeze

    # HKDF-Expand-Label takes a label of 7 to 255 bytes, "tls13 " included.
    EXPORTER_LABEL_LENGTH = 1..249

    CIPHER_SUITES_BY_NAME = CipherSuite::SUITES.values.to_h { |suite| [suite.name, suite] }.freeze
    GROUPS_BY_NAME = IANA::NAMED_GROUPS.invert.freeze
    SCHEMES_BY_NAME = SignatureScheme::SCHEMES.values.to_h { |scheme| [scheme.name, scheme] }.freeze

    def self.client(**options) = new(role: :client, **options)

    def self.server(**options) = new(role: :server, **options)

    # A client Config whose ClientHello depends only on the random and the
    # key shares: no extension permutation and no GREASE. For test vectors
    # and byte-for-byte comparisons.
    def self.deterministic(**options) = client(permute_extensions: false, grease: false, **options)

    attr_reader :role, :profile, :cipher_suites, :groups, :signature_algorithms, :signature_algorithms_cert,
      :alpn, :registry, :extensions, :max_handshake_message_size, :max_certificate_message_size,
      :max_certificate_chain_length, :permute_extensions, :grease, :exporter_labels, :record_size_limit,
      :trust_anchors, :verify_flags, :client_auth, :certificate_authorities, :require_server_name

    # The wire values of the Symbol settings above, in the same order.
    attr_reader :cipher_suite_ids, :group_ids, :signature_algorithm_ids, :signature_algorithm_cert_ids

    def initialize(
      role:,
      profile: Profile::TCP,
      cipher_suites: DEFAULT_CIPHER_SUITES,
      groups: DEFAULT_GROUPS,
      signature_algorithms: DEFAULT_SIGNATURE_ALGORITHMS,
      signature_algorithms_cert: DEFAULT_SIGNATURE_ALGORITHMS_CERT,
      alpn: [],
      registry: Extension::Registry::BUILTIN,
      extensions: [],
      max_handshake_message_size: 16 * 1024,
      max_certificate_message_size: 256 * 1024,
      max_certificate_chain_length: 10,
      permute_extensions: true,
      grease: true,
      exporter_labels: [],
      record_size_limit: nil,
      trust_anchors: [],
      verify_flags: 0,
      client_auth: :none,
      certificate_authorities: true,
      require_server_name: false
    )
      raise ArgumentError, "role must be :client or :server, not #{role.inspect}" unless %i[client server].include?(role)
      raise ArgumentError, "profile must be a Profile" unless profile.is_a?(Profile)
      @role = role
      @profile = profile

      @cipher_suites = names(:cipher_suites, cipher_suites, CIPHER_SUITES_BY_NAME)
      @cipher_suite_ids = @cipher_suites.map { |name| CIPHER_SUITES_BY_NAME.fetch(name).id }
      @groups = names(:groups, groups, GROUPS_BY_NAME)
      @group_ids = @groups.map { |name| GROUPS_BY_NAME.fetch(name) }
      @signature_algorithms = names(:signature_algorithms, signature_algorithms, SCHEMES_BY_NAME)
      unusable = @signature_algorithms.reject { |name| SCHEMES_BY_NAME.fetch(name).usable_in_certificate_verify? }
      unless unusable.empty?
        raise ArgumentError, "#{unusable.inspect} cannot sign a CertificateVerify; list them in signature_algorithms_cert"
      end
      @signature_algorithm_ids = @signature_algorithms.map { |name| SCHEMES_BY_NAME.fetch(name).id }
      @signature_algorithms_cert = names(:signature_algorithms_cert, signature_algorithms_cert, SCHEMES_BY_NAME)
      @signature_algorithm_cert_ids = @signature_algorithms_cert.map { |name| SCHEMES_BY_NAME.fetch(name).id }

      @alpn = check_alpn(alpn)
      raise ArgumentError, "registry must be an Extension::Registry" unless registry.is_a?(Extension::Registry)
      @registry = registry
      @extensions = check_extensions(extensions, registry)

      @max_handshake_message_size = positive(:max_handshake_message_size, max_handshake_message_size)
      @max_certificate_message_size = positive(:max_certificate_message_size, max_certificate_message_size)
      @max_certificate_chain_length = positive(:max_certificate_chain_length, max_certificate_chain_length)
      @permute_extensions = permute_extensions ? true : false
      @grease = grease ? true : false
      @exporter_labels = check_exporter_labels(exporter_labels)
      # RFC 8449: a value under 64 is an error, and TLS 1.3 allows a plaintext
      # of at most 2^14 bytes plus the content type.
      unless record_size_limit.nil? || (record_size_limit.is_a?(Integer) && record_size_limit.between?(64, (1 << 14) + 1))
        raise ArgumentError, "record_size_limit must be nil or in 64..16385"
      end
      @record_size_limit = record_size_limit

      unless trust_anchors.is_a?(Array) && trust_anchors.all? { |der| der.is_a?(String) }
        raise ArgumentError, "trust_anchors must be an Array of DER Strings"
      end
      @trust_anchors = trust_anchors.map(&:b)
      raise ArgumentError, "verify_flags must be an Integer" unless verify_flags.is_a?(Integer)
      @verify_flags = verify_flags

      unless %i[none optional required].include?(client_auth)
        raise ArgumentError, "client_auth must be :none, :optional or :required, not #{client_auth.inspect}"
      end
      raise ArgumentError, "client_auth is a server setting" if role == :client && client_auth != :none
      raise ArgumentError, "require_server_name is a server setting" if role == :client && require_server_name
      @client_auth = client_auth
      @certificate_authorities = certificate_authorities ? true : false
      @require_server_name = require_server_name ? true : false

      # Every setting above is a copy of what was given, so this freezes
      # nothing of the caller's.
      Ractor.make_shareable(self)
    end

    def client? = role == :client

    def server? = role == :server

    # A Config with some settings changed, checked and frozen like a new one.
    def with(
      profile: self.profile, cipher_suites: self.cipher_suites, groups: self.groups,
      signature_algorithms: self.signature_algorithms, signature_algorithms_cert: self.signature_algorithms_cert,
      alpn: self.alpn, registry: self.registry, extensions: self.extensions,
      max_handshake_message_size: self.max_handshake_message_size,
      max_certificate_message_size: self.max_certificate_message_size,
      max_certificate_chain_length: self.max_certificate_chain_length,
      permute_extensions: self.permute_extensions, grease: self.grease, exporter_labels: self.exporter_labels,
      record_size_limit: self.record_size_limit, trust_anchors: self.trust_anchors, verify_flags: self.verify_flags,
      client_auth: self.client_auth, certificate_authorities: self.certificate_authorities,
      require_server_name: self.require_server_name
    )
      Config.new(
        role:, profile:, cipher_suites:, groups:, signature_algorithms:, signature_algorithms_cert:, alpn:, registry:,
        extensions:, max_handshake_message_size:, max_certificate_message_size:, max_certificate_chain_length:,
        permute_extensions:, grease:, exporter_labels:, record_size_limit:, trust_anchors:, verify_flags:,
        client_auth:, certificate_authorities:, require_server_name:
      )
    end

    private def names(setting, given, table)
      raise ArgumentError, "#{setting} must be a non-empty Array of Symbols" unless given.is_a?(Array) && !given.empty?
      unknown = given.reject { |name| table.key?(name) }
      raise ArgumentError, "#{setting} has unknown or unsupported names: #{unknown.inspect}" unless unknown.empty?
      raise ArgumentError, "#{setting} lists a name twice" unless given.uniq.size == given.size
      given.dup
    end

    # RFC 7301: ProtocolName<1..2^8-1>.
    private def check_alpn(alpn)
      raise ArgumentError, "alpn must be an Array of Strings" unless alpn.is_a?(Array) && alpn.all? { |p| p.is_a?(String) }
      protocols = alpn.map(&:b)
      raise ArgumentError, "an ALPN protocol name is 1 to 255 bytes" unless protocols.all? { |p| p.bytesize.between?(1, 255) }
      raise ArgumentError, "alpn lists a protocol twice" unless protocols.uniq.size == protocols.size
      protocols
    end

    private def check_extensions(extensions, registry)
      raise ArgumentError, "extensions must be an Array" unless extensions.is_a?(Array)
      Config.check_extensions(extensions, registry)
      Ractor.make_shareable(extensions, copy: true)
    # A Proc cannot be copied (TypeError) and some objects cannot be made
    # shareable at all (Ractor::Error).
    rescue Ractor::Error, TypeError => e
      raise ArgumentError, "a Config is shared between Ractors, so its extensions cannot hold a Proc or an I/O: #{e.message}"
    end

    # The checks on extensions given from outside, shared with the ones a
    # Machine is given for one connection.
    def self.check_extensions(extensions, registry)
      types = extensions.map do |ext|
        type = ext.extension_type
        raise ArgumentError, "extension #{type} is set by the handshake itself" if RESERVED_EXTENSIONS.include?(type)
        raise ArgumentError, "extension #{type} is a GREASE value" if IANA.grease?(type)
        case ext
        when Extension::Opaque
          # Raw bytes need no codec.
        else
          # A typed value must be registered, so that the same type coming
          # back from the peer parses into the same class, not into Opaque.
          raise ArgumentError, "extension #{type} is not registered in the Config's registry" unless registry.registered?(type)
        end
        type
      end
      raise ArgumentError, "an extension type appears twice" unless types.uniq.size == types.size
    end

    private def check_exporter_labels(labels)
      unless labels.is_a?(Array) && labels.all? { |label| label.is_a?(String) }
        raise ArgumentError, "exporter_labels must be an Array of Strings"
      end
      labels = labels.map(&:b)
      unless labels.all? { |label| EXPORTER_LABEL_LENGTH.cover?(label.bytesize) }
        raise ArgumentError, "an exporter label is 1 to 249 bytes"
      end
      raise ArgumentError, "exporter_labels lists a label twice" unless labels.uniq.size == labels.size
      labels
    end

    private def positive(setting, value)
      raise ArgumentError, "#{setting} must be a positive Integer" unless value.is_a?(Integer) && value.positive?
      value
    end
  end
end
