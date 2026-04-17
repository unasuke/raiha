# frozen_string_literal: true

require_relative "../quic/wire/buffer"
require_relative "../quic/varint"
require_relative "frame"
require_relative "stream_type"

module Raiha
  module HTTP3
    module ControlStream
      # Parse an incoming unidirectional stream's payload. Returns [stream_type, frames]
      # when the stream type is recognized; returns [nil, nil] if the stream type is
      # not yet fully received.
      def self.parse_incoming(data)
        return [nil, []] if data.empty?

        buffer = Quic::Wire::Buffer.new(data)
        stream_type = buffer.read_varint
        return [stream_type, []] if stream_type != StreamType::CONTROL

        frames = [] #: Array[Frame]
        frames << Frame.parse(buffer) until buffer.eof?
        [stream_type, frames]
      end

      # Extract the peer's SETTINGS from a list of parsed frames, or nil if none.
      def self.extract_settings(frames)
        frames.find { |f| f.is_a?(SettingsFrame) }
      end
    end
  end
end
