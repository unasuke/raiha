# frozen_string_literal: true

require "securerandom"

module Raiha::Quic
  module Protocol
    class ConnectionID
      MAX_LENGTH = 20

      attr_reader :bytes

      def initialize(bytes = nil)
        @bytes = bytes || SecureRandom.random_bytes(8)
        validate!
      end

      def self.generate(length: 8)
        self.new(SecureRandom.random_bytes(length))
      end

      def self.from_bytes(bytes)
        self.new(bytes)
      end

      def length
        @bytes.bytesize
      end

      def ==(other)
        return false unless other.is_a?(ConnectionID)

        @bytes == other.bytes
      end
      alias eql? ==

      def hash
        @bytes.hash
      end

      def to_s
        @bytes.unpack1("H*")
      end

      def serialize
        @bytes
      end

      private def validate!
        raise ArgumentError, "Connection ID too long (#{@bytes.bytesize} > #{MAX_LENGTH})" if @bytes.bytesize > MAX_LENGTH
      end
    end
  end
end
