# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  class StopSendingFrame < Raiha::Quic::Wire::Frame
    attr_accessor :stream_id
    attr_accessor :application_protocol_error_code

    def self.parse(buffer)
      frame = self.new
      frame.stream_id = buffer.read_varint
      frame.application_protocol_error_code = buffer.read_varint
      frame
    end

    def serialize
      buf = Raiha::Quic::Wire::Buffer.new
      buf.write_varint(Type::STOP_SENDING)
      buf.write_varint(@stream_id)
      buf.write_varint(@application_protocol_error_code)
      buf.to_s
    end

    def frame_type
      Type::STOP_SENDING
    end
  end
end
