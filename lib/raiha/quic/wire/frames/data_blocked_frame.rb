# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  class DataBlockedFrame < Raiha::Quic::Wire::Frame
    attr_accessor :maximum_data

    def self.parse(buffer)
      frame = self.new
      frame.maximum_data = buffer.read_varint
      frame
    end

    def serialize
      buf = Raiha::Quic::Wire::Buffer.new
      buf.write_varint(Type::DATA_BLOCKED)
      buf.write_varint(@maximum_data)
      buf.to_s
    end

    def frame_type
      Type::DATA_BLOCKED
    end
  end
end
