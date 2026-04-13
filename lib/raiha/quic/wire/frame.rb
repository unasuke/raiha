# frozen_string_literal: true

module Raiha::Quic
  module Wire
    class Frame
      module Type
        PADDING = 0x00
        PING = 0x01
        ACK = 0x02
        ACK_ECN = 0x03
        RESET_STREAM = 0x04
        STOP_SENDING = 0x05
        CRYPTO = 0x06
        NEW_TOKEN = 0x07
        STREAM = (0x08..0x0f)
        MAX_DATA = 0x10
        MAX_STREAM_DATA = 0x11
        MAX_STREAMS_BIDI = 0x12
        MAX_STREAMS_UNI = 0x13
        DATA_BLOCKED = 0x14
        STREAM_DATA_BLOCKED = 0x15
        STREAMS_BLOCKED_BIDI = 0x16
        STREAMS_BLOCKED_UNI = 0x17
        NEW_CONNECTION_ID = 0x18
        RETIRE_CONNECTION_ID = 0x19
        PATH_CHALLENGE = 0x1a
        PATH_RESPONSE = 0x1b
        CONNECTION_CLOSE = 0x1c
        CONNECTION_CLOSE_APP = 0x1d
        HANDSHAKE_DONE = 0x1e
      end

      def self.parse(buffer)
        raise NotImplementedError
      end

      def serialize
        raise NotImplementedError
      end

      def frame_type
        raise NotImplementedError
      end

      def ack_eliciting?
        true
      end
    end
  end
end
