# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  class PingFrame < Raiha::Quic::Wire::Frame
    def self.parse(buffer)
      self.new
    end

    def serialize
      Raiha::Quic::Varint.encode(Type::PING)
    end

    def frame_type
      Type::PING
    end
  end
end
