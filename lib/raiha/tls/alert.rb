# frozen_string_literal: true

require_relative "../../tls"

module Raiha
  module TLS
    # Represents alerts of the TLS 1.3 protocol.
    #
    #  enum { warning(1), fatal(2), (255) } AlertLevel;
    #
    #  enum {
    #      close_notify(0),
    #      unexpected_message(10),
    #      bad_record_mac(20),
    #      record_overflow(22),
    #      handshake_failure(40),
    #      bad_certificate(42),
    #      unsupported_certificate(43),
    #      certificate_revoked(44),
    #      certificate_expired(45),
    #      certificate_unknown(46),
    #      illegal_parameter(47),
    #      unknown_ca(48),
    #      access_denied(49),
    #      decode_error(50),
    #      decrypt_error(51),
    #      protocol_version(70),
    #      insufficient_security(71),
    #      internal_error(80),
    #      inappropriate_fallback(86),
    #      user_canceled(90),
    #      missing_extension(109),
    #      unsupported_extension(110),
    #      unrecognized_name(112),
    #      bad_certificate_status_response(113),
    #      unknown_psk_identity(115),
    #      certificate_required(116),
    #      no_application_protocol(120),
    #      (255)
    #  } AlertDescription;
    #
    #  struct {
    #      AlertLevel level;
    #      AlertDescription description;
    #  } Alert;
    #
    # @see https://datatracker.ietf.org/doc/html/rfc8446#section-6
    class Alert
      # Abstract base class for all alerts.
      # @!attribute [r] kind
      #   @return [Symbol] Alert kind
      # @!attribute [r] level
      #   @return [Symbol] Alert level. +:warning+ or +:fatal+
      class Base
        attr_reader :kind
        attr_reader :level

        # @param error_message [String] Message of the error
        # @param kind [Symbol] Alert kind.
        # @param level [Symbol] Alert level. Accepts +:warning+ or +:fatal+
        # @raise [ArgumentError] if kind or level are unexpected, raises +ArgumentError+
        # @see https://www.rfc-editor.org/rfc/rfc8446.html#section-6
        # @see https://www.rfc-editor.org/rfc/rfc8446.html#appendix-B.2
        def initialize(error_message, kind:, level:)
          super(error_message)
          raise ArgumentError, "Unknown error kind #{kind}" unless KINDS.keys.include?(kind)
          raise ArgumentError, "Unknown alert level #{kind}" unless %i(warning fatal).include?(level)
          @kind = kind
          @level = level
        end
      end

      class ClosureAlert < Base
        KINDS = {
          close_notify: 0,
          user_canceled: 90,
        }
      end

      class ErrorAlert < Base
        KINDS = {
          bad_record_mac: 20,
          decryption_failed_reserved: 21,
          record_overflow: 22,
          decompression_failure_reserved: 30,
          handshake_failure: 40,
          no_certificate_reserved: 41,
          bad_certificate: 42,
          unsupported_certificate: 43,
          certificate_revoked: 44,
          certificate_expired: 45,
          certificate_unknown: 46,
          illegal_parameter: 47,
          unknown_ca: 48,
          access_denied: 49,
          decode_error: 50,
          decrypt_error: 51,
          export_restriction_reserved: 60,
          protocol_version: 70,
          insufficient_security: 71,
          internal_error: 80,
          inappropriate_fallback: 86,
          no_renegotiation_reserved: 100,
          missing_extension: 109,
          unsupported_extension: 110,
          certificate_unobtainable_reserved: 111,
          unrecognized_name: 112,
          bad_certificate_status_response: 113,
          bad_certificate_hash_value_reserved: 114,
          unknown_psk_identity: 115,
          certificate_required: 116,
          general_error: 117,
          no_application_protocol: 120,
        }
      end
    end
  end
end
