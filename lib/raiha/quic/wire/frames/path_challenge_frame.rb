# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  class PathChallengeFrame < Raiha::Quic::Wire::Frame
    attr_accessor :data

    def self.parse(buffer)
      frame = self.new
      frame.data = buffer.read(8)
      frame
    end

    def serialize
      buf = Raiha::Quic::Wire::Buffer.new
      buf.write_varint(Type::PATH_CHALLENGE)
      buf.write(@data)
      buf.to_s
    end

    def frame_type
      Type::PATH_CHALLENGE
    end
  end
end
