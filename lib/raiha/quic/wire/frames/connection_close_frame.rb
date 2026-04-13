# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  # RFC 9000 Section 19.19
  #
  #   CONNECTION_CLOSE Frame {
  #     Type (i) = 0x1c..0x1d,
  #     Error Code (i),
  #     [Frame Type (i)],    // only for 0x1c
  #     Reason Phrase Length (i),
  #     Reason Phrase (..),
  #   }
  class ConnectionCloseFrame < Raiha::Quic::Wire::Frame
    attr_accessor :error_code
    attr_accessor :trigger_frame_type
    attr_accessor :reason_phrase
    attr_accessor :application_error

    def initialize
      @error_code = 0
      @trigger_frame_type = nil
      @reason_phrase = ""
      @application_error = false
    end

    def self.parse(buffer, app: false)
      frame = self.new
      frame.application_error = app
      frame.error_code = buffer.read_varint
      frame.trigger_frame_type = buffer.read_varint unless app
      reason_length = buffer.read_varint
      frame.reason_phrase = buffer.read(reason_length) if reason_length > 0
      frame
    end

    def serialize
      buf = Raiha::Quic::Wire::Buffer.new
      buf.write_varint(@application_error ? Type::CONNECTION_CLOSE_APP : Type::CONNECTION_CLOSE)
      buf.write_varint(@error_code)
      buf.write_varint(@trigger_frame_type || 0) unless @application_error
      buf.write_varint(@reason_phrase.bytesize)
      buf.write(@reason_phrase) unless @reason_phrase.empty?
      buf.to_s
    end

    def frame_type
      @application_error ? Type::CONNECTION_CLOSE_APP : Type::CONNECTION_CLOSE
    end

    def ack_eliciting?
      false
    end
  end
end
