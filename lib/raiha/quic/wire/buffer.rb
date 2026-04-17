# frozen_string_literal: true

require "forwardable"
require_relative "../varint"

module Raiha::Quic
  module Wire
    class Buffer
      extend Forwardable

      def_delegators :@io, :write, :pos, :seek, :eof?

      def read(length)
        @io.read(length) or raise EOFError, "unexpected EOF reading #{length} bytes"
      end

      def initialize(data = nil)
        if data
          @io = StringIO.new(data)
        else
          @io = StringIO.new(String.new(encoding: "BINARY"))
        end
      end

      def read_uint8
        @io.read(1).unpack1("C")
      end

      def read_uint16
        @io.read(2).unpack1("n")
      end

      def read_uint32
        @io.read(4).unpack1("N")
      end

      def read_varint
        Varint.decode(@io)
      end

      def write_uint8(value)
        @io.write([value].pack("C"))
      end

      def write_uint16(value)
        @io.write([value].pack("n"))
      end

      def write_uint32(value)
        @io.write([value].pack("N"))
      end

      def write_varint(value)
        @io.write(Varint.encode(value))
      end

      def remaining
        @io.size - @io.pos
      end

      def to_s
        @io.string
      end

      def bytesize
        @io.string.bytesize
      end
    end
  end
end
