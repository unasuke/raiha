# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  # RFC 9000 Section 19.20
  #
  #   HANDSHAKE_DONE Frame {
  #     Type (i) = 0x1e,
  #   }
  class HandshakeDoneFrame < Raiha::Quic::Wire::Frame
    def self.parse(buffer)
      self.new
    end

    def serialize
      Raiha::Quic::Varint.encode(Type::HANDSHAKE_DONE)
    end

    def frame_type
      Type::HANDSHAKE_DONE
    end
  end
end
