# frozen_string_literal: true

require_relative "../error"
require_relative "../wire/frames/connection_close_frame"

module Raiha::Quic
  module Qerr
    class ApplicationError < ::Raiha::Quic::Error
      attr_reader :error_code
      attr_reader :reason_phrase

      def initialize(error_code, reason_phrase: "")
        @error_code = error_code
        @reason_phrase = reason_phrase
        super("Application Error: 0x#{error_code.to_s(16)} - #{reason_phrase}")
      end

      def to_connection_close_frame
        Wire::Frames::ConnectionCloseFrame.new.tap do |frame|
          frame.error_code = @error_code
          frame.reason_phrase = @reason_phrase
          frame.application_error = true
        end
      end
    end

    # RFC 9114 Section 8.1 - HTTP/3 Error Codes
    module Http3ErrorCode
      H3_NO_ERROR = 0x0100
      H3_GENERAL_PROTOCOL_ERROR = 0x0101
      H3_INTERNAL_ERROR = 0x0102
      H3_STREAM_CREATION_ERROR = 0x0103
      H3_CLOSED_CRITICAL_STREAM = 0x0104
      H3_FRAME_UNEXPECTED = 0x0105
      H3_FRAME_ERROR = 0x0106
      H3_EXCESSIVE_LOAD = 0x0107
      H3_ID_ERROR = 0x0108
      H3_SETTINGS_ERROR = 0x0109
      H3_MISSING_SETTINGS = 0x010a
      H3_REQUEST_REJECTED = 0x010b
      H3_REQUEST_CANCELLED = 0x010c
      H3_REQUEST_INCOMPLETE = 0x010d
      H3_MESSAGE_ERROR = 0x010e
      H3_CONNECT_ERROR = 0x010f
      H3_VERSION_FALLBACK = 0x0110
    end
  end
end
