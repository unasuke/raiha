# frozen_string_literal: true

require_relative "../codec"
require_relative "../extension"
require_relative "message"
require_relative "violation"

module Raiha::Next::TLS
  module Handshake
    # A ServerHello, or a HelloRetryRequest: RFC 9846 defines the latter as a
    # ServerHello whose random is a fixed value, not as a message type of its
    # own. The two differ only in which extensions they may carry, so parsing
    # picks the extension context from the random.
    class ServerHello < Data.define(
      :legacy_version, :random, :legacy_session_id_echo, :cipher_suite, :legacy_compression_method, :extensions
    )
      include Message
      include ExtensionLookup

      MSG_TYPE = 2

      HELLO_RETRY_REQUEST_RANDOM = ["CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"].pack("H*").freeze

      def self.parse_body(body, registry:)
        r = Codec::Reader.new(body)
        legacy_version = r.u16
        random = r.bytes(32)
        legacy_session_id_echo = r.opaque(1, max: 32)
        cipher_suite = r.u16
        legacy_compression_method = r.u8
        context = random == HELLO_RETRY_REQUEST_RANDOM ? :hello_retry_request : :server_hello #: Handshake::context
        extensions = Extension.read_list(r, context:, registry:, min: 6)
        r.finish!
        new(legacy_version:, random:, legacy_session_id_echo:, cipher_suite:, legacy_compression_method:, extensions:)
      end

      def msg_type = MSG_TYPE

      # The message type cannot tell the two apart, so a client must check
      # this on every ServerHello it receives.
      def hello_retry_request? = random == HELLO_RETRY_REQUEST_RANDOM

      # The last 8 bytes of a TLS 1.3 server's random when it negotiates TLS 1.2
      # or TLS 1.1 and below.
      DOWNGRADE_TLS12 = "DOWNGRD\x01".b.freeze
      DOWNGRADE_TLS11 = "DOWNGRD\x00".b.freeze

      # The checks a client makes on a ServerHello or HelloRetryRequest by
      # itself, in order; the first failure is returned. 3 must come before 4:
      # the downgrade sentinel matters only once supported_versions is known
      # to be absent, that is, when the server claims TLS 1.2 or lower.
      #
      # 5 needs no context: this implementation offers only TLS 1.3, so any
      # other selected_version was not offered. 1 holds only without
      # supported_versions: with it, a client ignores legacy_version (RFC
      # 8446 "Supported Versions": "clients MUST ignore the
      # ServerHello.legacy_version value").
      def validate
        # 2
        unless legacy_compression_method == 0
          return Violation.new(alert: :illegal_parameter, reason: :legacy_compression_method)
        end
        case (versions = extension(Extension::SupportedVersions::TYPE))
        when Extension::SupportedVersions::SH
          # 5
          return Violation.new(alert: :illegal_parameter, reason: :selected_version) unless versions.selected_version == 0x0304
        else
          # 1
          return Violation.new(alert: :protocol_version, reason: :legacy_version) unless legacy_version == 0x0303
          # 3
          tail = random.byteslice(24, 8)
          if tail == DOWNGRADE_TLS12 || tail == DOWNGRADE_TLS11
            return Violation.new(alert: :illegal_parameter, reason: :downgrade_sentinel)
          end
          # 4
          return Violation.new(alert: :protocol_version, reason: :supported_versions)
        end
        nil
      end

      def write_body(w)
        w.u16(legacy_version)
        w.bytes(random)
        w.vector(1, max: 32) { w.bytes(legacy_session_id_echo) }
        w.u16(cipher_suite)
        w.u8(legacy_compression_method)
        Extension.write_list(w, extensions, min: 6)
      end
    end
  end
end
