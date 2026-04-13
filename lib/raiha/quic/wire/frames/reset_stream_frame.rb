# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  class ResetStreamFrame < Raiha::Quic::Wire::Frame
    attr_accessor :stream_id
    attr_accessor :application_protocol_error_code
    attr_accessor :final_size

    def self.parse(buffer)
      frame = self.new
      frame.stream_id = buffer.read_varint
      frame.application_protocol_error_code = buffer.read_varint
      frame.final_size = buffer.read_varint
      frame
    end

    def serialize
      buf = Raiha::Quic::Wire::Buffer.new
      buf.write_varint(Type::RESET_STREAM)
      buf.write_varint(@stream_id)
      buf.write_varint(@application_protocol_error_code)
      buf.write_varint(@final_size)
      buf.to_s
    end

    def frame_type
      Type::RESET_STREAM
    end
  end
end
