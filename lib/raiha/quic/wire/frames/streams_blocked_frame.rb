# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  class StreamsBlockedFrame < Raiha::Quic::Wire::Frame
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
      buf.write_varint(@bidirectional ? Type::STREAMS_BLOCKED_BIDI : Type::STREAMS_BLOCKED_UNI)
      buf.write_varint(@maximum_streams)
      buf.to_s
    end

    def frame_type
      @bidirectional ? Type::STREAMS_BLOCKED_BIDI : Type::STREAMS_BLOCKED_UNI
    end
  end
end
