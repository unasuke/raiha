# frozen_string_literal: true

module Raiha::Next::HTTP3
  # The error codes of HTTP/3 (RFC 9114 "HTTP/3 Error Codes"), for closing
  # the connection and resetting streams, and the one HTTP Datagrams add
  # (RFC 9297). QPACK's are QPACK::ErrorCode.
  module ErrorCode
    NO_ERROR = 0x0100
    GENERAL_PROTOCOL_ERROR = 0x0101
    INTERNAL_ERROR = 0x0102
    STREAM_CREATION_ERROR = 0x0103
    CLOSED_CRITICAL_STREAM = 0x0104
    FRAME_UNEXPECTED = 0x0105
    FRAME_ERROR = 0x0106
    EXCESSIVE_LOAD = 0x0107
    ID_ERROR = 0x0108
    SETTINGS_ERROR = 0x0109
    MISSING_SETTINGS = 0x010a
    REQUEST_REJECTED = 0x010b
    REQUEST_CANCELLED = 0x010c
    REQUEST_INCOMPLETE = 0x010d
    MESSAGE_ERROR = 0x010e
    CONNECT_ERROR = 0x010f
    VERSION_FALLBACK = 0x0110
    DATAGRAM_ERROR = 0x33
  end
end
