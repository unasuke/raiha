# frozen_string_literal: true

require_relative "../error"
require_relative "buffer"
require_relative "frame"
require_relative "frames/padding_frame"
require_relative "frames/ping_frame"
require_relative "frames/ack_frame"
require_relative "frames/reset_stream_frame"
require_relative "frames/stop_sending_frame"
require_relative "frames/crypto_frame"
require_relative "frames/new_token_frame"
require_relative "frames/stream_frame"
require_relative "frames/max_data_frame"
require_relative "frames/max_stream_data_frame"
require_relative "frames/max_streams_frame"
require_relative "frames/data_blocked_frame"
require_relative "frames/stream_data_blocked_frame"
require_relative "frames/streams_blocked_frame"
require_relative "frames/new_connection_id_frame"
require_relative "frames/retire_connection_id_frame"
require_relative "frames/path_challenge_frame"
require_relative "frames/path_response_frame"
require_relative "frames/connection_close_frame"
require_relative "frames/handshake_done_frame"

module Raiha::Quic
  module Wire
    class FrameParser
      def self.parse(buffer)
        frames = [] #: Array[Frame]

        until buffer.eof?
          frame_type = buffer.read_varint

          frame = case frame_type
          when Frame::Type::PADDING
            Frames::PaddingFrame.parse(buffer)
          when Frame::Type::PING
            Frames::PingFrame.parse(buffer)
          when Frame::Type::ACK
            Frames::AckFrame.parse(buffer, ecn: false)
          when Frame::Type::ACK_ECN
            Frames::AckFrame.parse(buffer, ecn: true)
          when Frame::Type::RESET_STREAM
            Frames::ResetStreamFrame.parse(buffer)
          when Frame::Type::STOP_SENDING
            Frames::StopSendingFrame.parse(buffer)
          when Frame::Type::CRYPTO
            Frames::CryptoFrame.parse(buffer)
          when Frame::Type::NEW_TOKEN
            Frames::NewTokenFrame.parse(buffer)
          when Frame::Type::STREAM
            Frames::StreamFrame.parse(buffer, frame_type)
          when Frame::Type::MAX_DATA
            Frames::MaxDataFrame.parse(buffer)
          when Frame::Type::MAX_STREAM_DATA
            Frames::MaxStreamDataFrame.parse(buffer)
          when Frame::Type::MAX_STREAMS_BIDI
            Frames::MaxStreamsFrame.parse(buffer, bidirectional: true)
          when Frame::Type::MAX_STREAMS_UNI
            Frames::MaxStreamsFrame.parse(buffer, bidirectional: false)
          when Frame::Type::DATA_BLOCKED
            Frames::DataBlockedFrame.parse(buffer)
          when Frame::Type::STREAM_DATA_BLOCKED
            Frames::StreamDataBlockedFrame.parse(buffer)
          when Frame::Type::STREAMS_BLOCKED_BIDI
            Frames::StreamsBlockedFrame.parse(buffer, bidirectional: true)
          when Frame::Type::STREAMS_BLOCKED_UNI
            Frames::StreamsBlockedFrame.parse(buffer, bidirectional: false)
          when Frame::Type::NEW_CONNECTION_ID
            Frames::NewConnectionIdFrame.parse(buffer)
          when Frame::Type::RETIRE_CONNECTION_ID
            Frames::RetireConnectionIdFrame.parse(buffer)
          when Frame::Type::PATH_CHALLENGE
            Frames::PathChallengeFrame.parse(buffer)
          when Frame::Type::PATH_RESPONSE
            Frames::PathResponseFrame.parse(buffer)
          when Frame::Type::CONNECTION_CLOSE
            Frames::ConnectionCloseFrame.parse(buffer, app: false)
          when Frame::Type::CONNECTION_CLOSE_APP
            Frames::ConnectionCloseFrame.parse(buffer, app: true)
          when Frame::Type::HANDSHAKE_DONE
            Frames::HandshakeDoneFrame.parse(buffer)
          else
            raise Raiha::Quic::Error, "Unknown frame type: 0x#{frame_type.to_s(16)}"
          end

          frames << frame
        end

        frames
      end
    end
  end
end
