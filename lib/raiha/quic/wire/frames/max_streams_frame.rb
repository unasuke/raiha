# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  class MaxStreamsFrame < Raiha::Quic::Wire::Frame
    attr_accessor :maximum_streams
    attr_accessor :bidirectional

    def self.parse(buffer, bidirectional:)
      frame = self.new
      frame.bidirectional = bidirectional
      frame.maximum_streams = buffer.read_varint
      frame
    end

    def serialize
      buf = Raiha::Quic::Wire::Buffer.new
      buf.write_varint(@bidirectional ? Type::MAX_STREAMS_BIDI : Type::MAX_STREAMS_UNI)
      buf.write_varint(@maximum_streams)
      buf.to_s
    end

    def frame_type
      @bidirectional ? Type::MAX_STREAMS_BIDI : Type::MAX_STREAMS_UNI
    end
  end
end
