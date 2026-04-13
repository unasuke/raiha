# frozen_string_literal: true

require_relative "../frame"
require_relative "../../protocol/connection_id"

module Raiha::Quic::Wire::Frames
  class NewConnectionIdFrame < Raiha::Quic::Wire::Frame
    attr_accessor :sequence_number
    attr_accessor :retire_prior_to
    attr_accessor :connection_id
    attr_accessor :stateless_reset_token

    def self.parse(buffer)
      frame = self.new
      frame.sequence_number = buffer.read_varint
      frame.retire_prior_to = buffer.read_varint
      connection_id_length = buffer.read_uint8
      frame.connection_id = Raiha::Quic::Protocol::ConnectionID.from_bytes(buffer.read(connection_id_length))
      frame.stateless_reset_token = buffer.read(16)
      frame
    end

    def serialize
      buf = Raiha::Quic::Wire::Buffer.new
      buf.write_varint(Type::NEW_CONNECTION_ID)
      buf.write_varint(@sequence_number)
      buf.write_varint(@retire_prior_to)
      buf.write_uint8(@connection_id.length)
      buf.write(@connection_id.serialize)
      buf.write(@stateless_reset_token)
      buf.to_s
    end

    def frame_type
      Type::NEW_CONNECTION_ID
    end
  end
end
