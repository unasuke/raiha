# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  # RFC 9000 Section 19.8
  #
  #   STREAM Frame {
  #     Type (i) = 0x08..0x0f,
  #     Stream ID (i),
  #     [Offset (i)],
  #     [Length (i)],
  #     Stream Data (..),
  #   }
  #
  # Type bits: 0x04 = FIN, 0x02 = LEN, 0x01 = OFF
  class StreamFrame < Raiha::Quic::Wire::Frame
    attr_accessor :stream_id
    attr_accessor :offset
    attr_accessor :data
    attr_accessor :fin

    def initialize
      @offset = 0
      @data = "".b
      @fin = false
    end

    def self.parse(buffer, type_byte)
      frame = self.new
      has_offset = (type_byte & 0x04) != 0
      has_length = (type_byte & 0x02) != 0
      frame.fin = (type_byte & 0x01) != 0

      frame.stream_id = buffer.read_varint
      frame.offset = has_offset ? buffer.read_varint : 0

      if has_length
        length = buffer.read_varint
        frame.data = buffer.read(length)
      else
        frame.data = buffer.read(buffer.remaining)
      end

      frame
    end

    def serialize
      type_byte = 0x08
      type_byte |= 0x04 if @offset > 0
      type_byte |= 0x02  # Always include length
      type_byte |= 0x01 if @fin

      buf = Raiha::Quic::Wire::Buffer.new
      buf.write_varint(type_byte)
      buf.write_varint(@stream_id)
      buf.write_varint(@offset) if @offset > 0
      buf.write_varint(@data.bytesize)
      buf.write(@data)
      buf.to_s
    end

    def frame_type
      Type::STREAM
    end
  end
end
