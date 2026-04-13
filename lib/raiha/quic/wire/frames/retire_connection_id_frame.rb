# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  class RetireConnectionIdFrame < Raiha::Quic::Wire::Frame
    attr_accessor :sequence_number

    def self.parse(buffer)
      frame = self.new
      frame.sequence_number = buffer.read_varint
      frame
    end

    def serialize
      buf = Raiha::Quic::Wire::Buffer.new
      buf.write_varint(Type::RETIRE_CONNECTION_ID)
      buf.write_varint(@sequence_number)
      buf.to_s
    end

    def frame_type
      Type::RETIRE_CONNECTION_ID
    end
  end
end
