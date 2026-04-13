# frozen_string_literal: true

module Raiha::Quic
  module Qerr
    # RFC 9000 Section 20.1 - Transport Error Codes
    module TransportErrorCode
      NO_ERROR = 0x00
      INTERNAL_ERROR = 0x01
      CONNECTION_REFUSED = 0x02
      FLOW_CONTROL_ERROR = 0x03
      STREAM_LIMIT_ERROR = 0x04
      STREAM_STATE_ERROR = 0x05
      FINAL_SIZE_ERROR = 0x06
      FRAME_ENCODING_ERROR = 0x07
      TRANSPORT_PARAMETER_ERROR = 0x08
      CONNECTION_ID_LIMIT_ERROR = 0x09
      PROTOCOL_VIOLATION = 0x0a
      INVALID_TOKEN = 0x0b
      APPLICATION_ERROR = 0x0c
      CRYPTO_BUFFER_EXCEEDED = 0x0d
      KEY_UPDATE_ERROR = 0x0e
      AEAD_LIMIT_REACHED = 0x0f
      NO_VIABLE_PATH = 0x10

      CRYPTO_ERROR_BASE = 0x0100

      DESCRIPTIONS = {
        NO_ERROR => "No error",
        INTERNAL_ERROR => "Implementation error",
        CONNECTION_REFUSED => "Server refuses a connection",
        FLOW_CONTROL_ERROR => "Flow control error",
        STREAM_LIMIT_ERROR => "Too many streams opened",
        STREAM_STATE_ERROR => "Frame received in invalid stream state",
        FINAL_SIZE_ERROR => "Change to final size",
        FRAME_ENCODING_ERROR => "Frame encoding error",
        TRANSPORT_PARAMETER_ERROR => "Error in transport parameters",
        CONNECTION_ID_LIMIT_ERROR => "Too many connection IDs received",
        PROTOCOL_VIOLATION => "Generic protocol violation",
        INVALID_TOKEN => "Invalid Token received",
        APPLICATION_ERROR => "Application error",
        CRYPTO_BUFFER_EXCEEDED => "CRYPTO data buffer overflowed",
        KEY_UPDATE_ERROR => "Invalid packet protection update",
        AEAD_LIMIT_REACHED => "Excessive use of packet protection keys",
        NO_VIABLE_PATH => "No viable network path exists",
      }.freeze

      def self.description(code)
        if code >= CRYPTO_ERROR_BASE && code < CRYPTO_ERROR_BASE + 256
          tls_alert = code - CRYPTO_ERROR_BASE
          "TLS alert: #{tls_alert_description(tls_alert)}"
        else
          DESCRIPTIONS[code] || "Unknown error (0x#{code.to_s(16)})"
        end
      end

      def self.crypto_error(tls_alert_code)
        CRYPTO_ERROR_BASE + tls_alert_code
      end

      private_class_method def self.tls_alert_description(code)
        case code
        when 0 then "close_notify"
        when 10 then "unexpected_message"
        when 20 then "bad_record_mac"
        when 40 then "handshake_failure"
        when 42 then "bad_certificate"
        when 43 then "unsupported_certificate"
        when 44 then "certificate_revoked"
        when 45 then "certificate_expired"
        when 46 then "certificate_unknown"
        when 47 then "illegal_parameter"
        when 48 then "unknown_ca"
        when 50 then "decode_error"
        when 51 then "decrypt_error"
        when 70 then "protocol_version"
        when 71 then "insufficient_security"
        when 80 then "internal_error"
        when 86 then "inappropriate_fallback"
        when 90 then "user_canceled"
        when 109 then "missing_extension"
        when 110 then "unsupported_extension"
        when 112 then "unrecognized_name"
        when 113 then "bad_certificate_status_response"
        when 115 then "unknown_psk_identity"
        when 116 then "certificate_required"
        when 120 then "no_application_protocol"
        else "unknown (#{code})"
        end
      end
    end
  end
end
