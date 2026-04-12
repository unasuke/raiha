# frozen_string_literal: true

module Raiha::Quic
  module Protocol
    # RFC 9000 Section 2.1 - Stream Types and Identifiers
    #
    # The least significant two bits of a stream ID identify the stream type:
    #   0x00: Client-Initiated, Bidirectional
    #   0x01: Server-Initiated, Bidirectional
    #   0x02: Client-Initiated, Unidirectional
    #   0x03: Server-Initiated, Unidirectional
    class StreamID
      attr_reader :value

      def initialize(value)
        @value = value
      end

      def client_initiated?
        (@value & 0x01) == 0
      end

      def server_initiated?
        (@value & 0x01) == 1
      end

      def bidirectional?
        (@value & 0x02) == 0
      end

      def unidirectional?
        (@value & 0x02) == 2
      end

      def initiator
        client_initiated? ? Perspective::CLIENT : Perspective::SERVER
      end

      def self.next_bidirectional(perspective, current_max)
        base = perspective == Perspective::CLIENT ? 0 : 1
        self.new((current_max || -4) + 4 + base)
      end

      def self.next_unidirectional(perspective, current_max)
        base = perspective == Perspective::CLIENT ? 2 : 3
        self.new((current_max || -4) + 4 + base)
      end

      def ==(other)
        return false unless other.is_a?(StreamID)

        @value == other.value
      end
      alias eql? ==

      def hash
        @value.hash
      end

      def to_i
        @value
      end
    end
  end
end
