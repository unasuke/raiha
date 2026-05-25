# frozen_string_literal: true

module Raiha::Quic
  module AckHandler
    class SentPacketHandler
      class SentPacket
        attr_reader :packet_number
        attr_reader :frames
        attr_reader :sent_time
        attr_reader :size
        attr_reader :ack_eliciting
        attr_reader :in_flight

        def initialize(packet_number:, frames:, sent_time:, size:, ack_eliciting:, in_flight:)
          @packet_number = packet_number
          @frames = frames
          @sent_time = sent_time
          @size = size
          @ack_eliciting = ack_eliciting
          @in_flight = in_flight
        end

        def to_h
          {
            packet_number: @packet_number,
            frames: @frames,
            sent_time: @sent_time,
            size: @size,
            ack_eliciting: @ack_eliciting,
            in_flight: @in_flight
          }
        end

        def ==(other)
          return false unless other.is_a?(self.class)

          to_h == other.to_h
        end
        alias eql? ==

        def hash
          to_h.hash
        end

        def inspect
          "#<#{self.class} packet_number=#{@packet_number.value} size=#{@size} " \
            "ack_eliciting=#{@ack_eliciting} in_flight=#{@in_flight}>"
        end
      end
    end
  end
end
