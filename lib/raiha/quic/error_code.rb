# frozen_string_literal: true

module Raiha::QUIC
  # The transport error codes of RFC 9000 "Transport Error Codes".
  module ErrorCode
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

    # CRYPTO_ERROR is a range: 0x0100 plus the TLS alert.
    CRYPTO_ERROR_BASE = 0x0100

    def self.crypto_error(alert_code)
      raise ArgumentError, "a TLS alert is 0..255, not #{alert_code.inspect}" unless alert_code.is_a?(Integer) && alert_code.between?(0, 0xff)
      CRYPTO_ERROR_BASE + alert_code
    end
  end
end
