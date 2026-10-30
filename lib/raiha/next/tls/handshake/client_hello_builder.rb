# frozen_string_literal: true

require_relative "../config"
require_relative "../crypto"
require_relative "../extension"
require_relative "../profile"
require_relative "client_hello"

module Raiha::Next::TLS
  module Handshake
    # Builds the ClientHello a client opens with, and the second one after a
    # HelloRetryRequest.
    #
    # The random comes first. The GREASE values (RFC 8701) and the order of
    # the extensions are derived from it, so the second ClientHello, which
    # keeps the random, keeps them too, and a connection needs no seed of its
    # own. Extensions are shuffled once per connection, as Chrome does, unless
    # `permute_extensions` is off; a GREASE extension stays first and another
    # last, since some servers cannot handle an empty extension at the end.
    module ClientHelloBuilder
      # The ClientHello and the key pairs behind its key shares.
      class Built < Data.define(:client_hello, :key_pairs)
      end

      TLS13 = 0x0304
      LEGACY_VERSION = 0x0303

      # The order of the extensions without permutation. User extensions come
      # after these, quic_transport_parameters first among them.
      FIXED_ORDER = [
        Extension::ServerName::TYPE, Extension::SupportedVersions::TYPE, Extension::SupportedGroups::TYPE,
        Extension::KeyShare::TYPE, Extension::SignatureAlgorithms::TYPE, Extension::SignatureAlgorithmsCert::TYPE,
        Extension::PskKeyExchangeModes::TYPE, Extension::Alpn::TYPE, Extension::RecordSizeLimit::TYPE,
        Extension::CompressCertificate::TYPE, Extension::PostHandshakeAuth::TYPE, Profile::QUIC_TRANSPORT_PARAMETERS,
        Extension::Cookie::TYPE
      ].freeze

      PADDING = 21

      # The only PSK key exchange mode offered: a resumption keeps forward
      # secrecy only with a key exchange of its own.
      PSK_DHE_KE = 1

      # Where the GREASE values are taken from the seed.
      GREASE_SLOTS = { cipher_suite: 0, group: 1, version: 2, first_extension: 3, last_extension: 4 }.freeze #: Hash[Symbol, Integer]

      # `server_name` is the name in normal form, or nil to send no SNI (an IP
      # address). `extensions` are this connection's own, beside the
      # Config's. A key share is offered for the first group of the Config.
      def self.build(config:, keyring:, server_name:, extensions: [])
        random = keyring.random_bytes(32)
        legacy_session_id = config.profile.compatibility_mode ? keyring.random_bytes(32) : "".b
        seed = Crypto.hash(:sha256, "raiha ClientHello seed".b + random)
        # @type var grease: Hash[Symbol, Integer]
        grease = config.grease ? GREASE_SLOTS.transform_values { |slot| grease_value(seed, slot) } : {}
        if grease[:first_extension] && grease[:first_extension] == grease[:last_extension]
          grease[:last_extension] ^= 0x1010
        end

        key_pair = keyring.key_exchange.generate(config.groups.fetch(0))
        shares = [Extension::KeyShare::Entry.new(group: Config::GROUPS_BY_NAME.fetch(key_pair.group), key_exchange: key_pair.public_bytes)]
        shares.unshift(Extension::KeyShare::Entry.new(group: grease.fetch(:group), key_exchange: "\x00".b)) if config.grease

        built = {} #: Hash[Integer, Extension::_Extension]
        built[Extension::ServerName::TYPE] = Extension::ServerName::CH.new(host_name: server_name) if server_name
        built[Extension::SupportedVersions::TYPE] =
          Extension::SupportedVersions::CH.new(versions: [*grease.values_at(:version).compact, TLS13])
        built[Extension::SupportedGroups::TYPE] =
          Extension::SupportedGroups.new(named_group_list: [*grease.values_at(:group).compact, *config.group_ids])
        built[Extension::KeyShare::TYPE] = Extension::KeyShare::CH.new(client_shares: shares)
        built[Extension::SignatureAlgorithms::TYPE] =
          Extension::SignatureAlgorithms.new(supported_signature_algorithms: config.signature_algorithm_ids)
        unless config.signature_algorithm_cert_ids == config.signature_algorithm_ids
          built[Extension::SignatureAlgorithmsCert::TYPE] =
            Extension::SignatureAlgorithmsCert.new(supported_signature_algorithms: config.signature_algorithm_cert_ids)
        end
        # A client that resumes says how it takes a PSK, so that a server
        # issues it tickets: psk_dhe_ke alone.
        built[Extension::PskKeyExchangeModes::TYPE] = Extension::PskKeyExchangeModes.new(ke_modes: [PSK_DHE_KE]) if config.resumption
        built[Extension::Alpn::TYPE] = Extension::Alpn.new(protocol_name_list: config.alpn) unless config.alpn.empty?
        if (limit = config.record_size_limit)
          built[Extension::RecordSizeLimit::TYPE] = Extension::RecordSizeLimit.new(record_size_limit: limit)
        end
        given = config.extensions + extensions
        given.each { |ext| built[ext.extension_type] = ext }

        ordered = FIXED_ORDER.filter_map { |type| built[type] } + given.reject { |ext| FIXED_ORDER.include?(ext.extension_type) }
        if config.permute_extensions
          ordered = ordered.shuffle(random: Random.new(seed.unpack1("Q>")))
        end
        if config.grease
          ordered.unshift(Extension::Opaque.new(type: grease.fetch(:first_extension), data: "".b))
          ordered.push(Extension::Opaque.new(type: grease.fetch(:last_extension), data: "\x00".b))
        end

        cipher_suites = [*grease.values_at(:cipher_suite).compact, *config.cipher_suite_ids]
        client_hello = ClientHello.new(
          legacy_version: LEGACY_VERSION, random:, legacy_session_id:, cipher_suites:,
          legacy_compression_methods: [0], extensions: ordered
        )
        Built.new(client_hello:, key_pairs: [key_pair])
      end

      # The second ClientHello, from the first and the HelloRetryRequest
      # alone, never the Config: RFC 9846 "Client Hello" allows only these
      # changes, and copying everything else in place keeps the two the same
      # by construction, order included. The block makes the key share for
      # the group the server asked for.
      #
      # - key_share: a single entry for the requested group, in place; kept
      #   when the HelloRetryRequest asks only for a cookie.
      # - early_data: removed.
      # - cookie: the server's, replacing ours or inserted before
      #   pre_shared_key or padding, whichever comes first, or at the end.
      def self.retry(ch1, hrr)
        share = case (requested = hrr.extension(Extension::KeyShare::TYPE))
          when Extension::KeyShare::HRR then yield(requested.selected_group)
          end
        cookie = hrr.extension(Extension::Cookie::TYPE)
        extensions = ch1.extensions.filter_map do |ext|
          case ext.extension_type
          when Extension::EarlyData::TYPE then nil
          when Extension::KeyShare::TYPE then share ? Extension::KeyShare::CH.new(client_shares: [share]) : ext
          when Extension::Cookie::TYPE then cookie
          else ext
          end
        end
        had_cookie = ch1.extensions.any? { |ext| ext.extension_type == Extension::Cookie::TYPE }
        if cookie && !had_cookie
          at = extensions.index { |ext| [Extension::PreSharedKey::TYPE, PADDING].include?(ext.extension_type) } || extensions.size
          extensions.insert(at, cookie)
        end
        ch1.with(extensions:)
      end

      # One of the 16 GREASE values 0x0A0A, 0x1A1A, ..., 0xFAFA, from a byte
      # of the seed.
      private_class_method def self.grease_value(seed, slot)
        nibble = seed.getbyte(slot).to_i & 0xf0
        ((nibble | 0x0a) << 8) | nibble | 0x0a
      end
    end
  end
end
