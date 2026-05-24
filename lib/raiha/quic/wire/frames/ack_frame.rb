# frozen_string_literal: true

require_relative "../frame"

module Raiha::Quic::Wire::Frames
  # RFC 9000 Section 19.3
  #
  #   ACK Frame {
  #     Type (i) = 0x02..0x03,
  #     Largest Acknowledged (i),
  #     ACK Delay (i),
  #     ACK Range Count (i),
  #     First ACK Range (i),
  #     ACK Range (..) ...,
  #     [ECN Counts (..)],
  #   }
  class AckFrame < Raiha::Quic::Wire::Frame
    AckRange = Data.define(:gap, :ack_range_length)

    attr_accessor :largest_acknowledged
    attr_accessor :ack_delay
    attr_accessor :ack_ranges
    attr_accessor :ecn_counts

    def initialize
      @ack_ranges = []
      @ecn_counts = nil
    end

    def self.parse(buffer, ecn: false)
      frame = self.new
      frame.largest_acknowledged = buffer.read_varint
      frame.ack_delay = buffer.read_varint
      ack_range_count = buffer.read_varint
      first_ack_range = buffer.read_varint
      frame.ack_ranges << AckRange.new(0, first_ack_range)

      ack_range_count.times do
        gap = buffer.read_varint
        ack_range_length = buffer.read_varint
        frame.ack_ranges << AckRange.new(gap, ack_range_length)
      end

      if ecn
        frame.ecn_counts = {
          ect0: buffer.read_varint,
          ect1: buffer.read_varint,
          ecn_ce: buffer.read_varint,
        }
      end

      frame
    end

    def serialize
      buf = Raiha::Quic::Wire::Buffer.new
      buf.write_varint(ecn? ? Type::ACK_ECN : Type::ACK)
      buf.write_varint(@largest_acknowledged)
      buf.write_varint(@ack_delay)
      buf.write_varint(@ack_ranges.length - 1)
      buf.write_varint(@ack_ranges.first.ack_range_length)

      (@ack_ranges[1..] || []).each do |range|
        buf.write_varint(range.gap)
        buf.write_varint(range.ack_range_length)
      end

      ecn_counts = @ecn_counts
      if ecn_counts
        buf.write_varint(ecn_counts[:ect0])
        buf.write_varint(ecn_counts[:ect1])
        buf.write_varint(ecn_counts[:ecn_ce])
      end

      buf.to_s
    end

    def frame_type
      ecn? ? Type::ACK_ECN : Type::ACK
    end

    def ack_eliciting?
      false
    end

    private def ecn?
      !@ecn_counts.nil?
    end
  end
end
