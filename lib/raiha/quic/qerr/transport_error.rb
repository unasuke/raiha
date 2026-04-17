# frozen_string_literal: true

require_relative "error_code"
require_relative "../error"
require_relative "../wire/frames/connection_close_frame"

module Raiha::Quic
  module Qerr
    class TransportError < ::Raiha::Quic::Error
      attr_reader :error_code
      attr_reader :frame_type
      attr_reader :reason_phrase

      def initialize(error_code, frame_type: nil, reason_phrase: "")
        @error_code = error_code
        @frame_type = frame_type
        @reason_phrase = reason_phrase
        super(build_message)
      end

      def to_connection_close_frame
        Wire::Frames::ConnectionCloseFrame.new.tap do |frame|
          frame.error_code = @error_code
          frame.trigger_frame_type = @frame_type || 0
          frame.reason_phrase = @reason_phrase
          frame.application_error = false
        end
      end

      private def build_message
        message = "QUIC Transport Error: #{TransportErrorCode.description(@error_code)}"
        message += " (frame type: 0x#{@frame_type.to_s(16)})" if @frame_type
        message += " - #{@reason_phrase}" unless @reason_phrase.empty?
        message
      end
    end

    class InternalError < TransportError
      def initialize(reason_phrase = "")
        super(TransportErrorCode::INTERNAL_ERROR, reason_phrase: reason_phrase)
      end
    end

    class FlowControlError < TransportError
      def initialize(reason_phrase = "")
        super(TransportErrorCode::FLOW_CONTROL_ERROR, reason_phrase: reason_phrase)
      end
    end

    class StreamLimitError < TransportError
      def initialize(reason_phrase = "")
        super(TransportErrorCode::STREAM_LIMIT_ERROR, reason_phrase: reason_phrase)
      end
    end

    class StreamStateError < TransportError
      def initialize(frame_type: nil, reason_phrase: "")
        super(TransportErrorCode::STREAM_STATE_ERROR, frame_type: frame_type, reason_phrase: reason_phrase)
      end
    end

    class FinalSizeError < TransportError
      def initialize(reason_phrase = "")
        super(TransportErrorCode::FINAL_SIZE_ERROR, reason_phrase: reason_phrase)
      end
    end

    class FrameEncodingError < TransportError
      def initialize(frame_type: nil, reason_phrase: "")
        super(TransportErrorCode::FRAME_ENCODING_ERROR, frame_type: frame_type, reason_phrase: reason_phrase)
      end
    end

    class TransportParameterError < TransportError
      def initialize(reason_phrase = "")
        super(TransportErrorCode::TRANSPORT_PARAMETER_ERROR, reason_phrase: reason_phrase)
      end
    end

    class ProtocolViolation < TransportError
      def initialize(frame_type: nil, reason_phrase: "")
        super(TransportErrorCode::PROTOCOL_VIOLATION, frame_type: frame_type, reason_phrase: reason_phrase)
      end
    end

    class CryptoError < TransportError
      def initialize(tls_alert_code, reason_phrase: "")
        super(TransportErrorCode.crypto_error(tls_alert_code), reason_phrase: reason_phrase)
      end
    end
  end
end
