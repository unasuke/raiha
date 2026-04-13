# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  # RFC 9000 Section 19.6
  #
  #   CRYPTO Frame {
  #     Type (i) = 0x06,
  #     Offset (i),
  #     Length (i),
  #     Crypto Data (..),
  #   }
  class CryptoFrame < Raiha::Quic::Wire::Frame
    attr_accessor :offset
    attr_accessor :data

    def self.parse(buffer)
      frame = self.new
      frame.offset = buffer.read_varint
      length = buffer.read_varint
      frame.data = buffer.read(length)
      frame
    end

    def serialize
      buf = Raiha::Quic::Wire::Buffer.new
      buf.write_varint(Type::CRYPTO)
      buf.write_varint(@offset)
      buf.write_varint(@data.bytesize)
      buf.write(@data)
      buf.to_s
    end

    def frame_type
      Type::CRYPTO
    end
  end
end
