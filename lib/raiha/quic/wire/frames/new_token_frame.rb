# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  class NewTokenFrame < Raiha::Quic::Wire::Frame
    attr_accessor :token

    def self.parse(buffer)
      frame = self.new
      token_length = buffer.read_varint
      frame.token = buffer.read(token_length)
      frame
    end

    def serialize
      buf = Raiha::Quic::Wire::Buffer.new
      buf.write_varint(Type::NEW_TOKEN)
      buf.write_varint(@token.bytesize)
      buf.write(@token)
      buf.to_s
    end

    def frame_type
      Type::NEW_TOKEN
    end
  end
end
