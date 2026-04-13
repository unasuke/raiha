# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  class MaxStreamDataFrame < Raiha::Quic::Wire::Frame
    attr_accessor :stream_id
    attr_accessor :maximum_stream_data

    def self.parse(buffer)
      frame = self.new
      frame.stream_id = buffer.read_varint
      frame.maximum_stream_data = buffer.read_varint
      frame
    end

    def serialize
      buf = Raiha::Quic::Wire::Buffer.new
      buf.write_varint(Type::MAX_STREAM_DATA)
      buf.write_varint(@stream_id)
      buf.write_varint(@maximum_stream_data)
      buf.to_s
    end

    def frame_type
      Type::MAX_STREAM_DATA
    end
  end
end
