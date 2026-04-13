# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  class MaxDataFrame < Raiha::Quic::Wire::Frame
    attr_accessor :maximum_data

    def self.parse(buffer)
      frame = self.new
      frame.maximum_data = buffer.read_varint
      frame
    end

    def serialize
      buf = Raiha::Quic::Wire::Buffer.new
      buf.write_varint(Type::MAX_DATA)
      buf.write_varint(@maximum_data)
      buf.to_s
    end

    def frame_type
      Type::MAX_DATA
    end
  end
end
