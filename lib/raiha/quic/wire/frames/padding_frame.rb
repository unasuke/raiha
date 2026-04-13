# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  class PaddingFrame < Raiha::Quic::Wire::Frame
    def self.parse(buffer)
      self.new
    end

    def serialize
      Raiha::Quic::Varint.encode(Type::PADDING)
    end

    def frame_type
      Type::PADDING
    end

    def ack_eliciting?
      false
    end
  end
end
