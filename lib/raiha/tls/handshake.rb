# frozen_string_literal: true

require "securerandom"
require "stringio"
require_relative "cipher_suite"
require_relative "error"

module Raiha
  module TLS
    class Handshake
      HANDSHAKE_TYPE = {
        client_hello: 1,
        server_hello: 2,
        new_session_ticket: 4,
        end_of_early_data: 5,
        encrypted_extensions: 8,
        certificate: 11,
        certificate_request: 13,
        certificate_verify: 15,
        finished: 20,
        key_update: 24,
        message_hash: 254
      }.freeze

      attr_accessor :handshake_type
      attr_accessor :length
      attr_accessor :message
      attr_accessor :raw_bytes

      def serialize
        return @raw_bytes.dup if @raw_bytes

        buf = String.new(encoding: "BINARY")
        buf << [handshake_type].pack("C*")
        serialized_message = message.serialize
        buf << [serialized_message.bytesize].pack("N").byteslice(1..) # uint24
        buf << serialized_message
        buf
      end

      def self.deserialize(data)
        hs = self.new
        buf = StringIO.new(data)
        type = buf.read(1).unpack1("C")
        raise Raiha::TLS::Error, "unknown handshake type: #{type}" unless HANDSHAKE_TYPE.value?(type)

        hs.handshake_type = type
        hs.length = ("\x00" + buf.read(3)).unpack1("N")
        body = buf.read
        return nil if body.bytesize != hs.length

        hs.message = Message.deserialize(data: body, type: hs.handshake_type)
        hs.raw_bytes = data[0, 4 + hs.length]
        hs
      end

      def self.deserialize_multiple(data)
        handshakes = [] #: Array[Handshake]
        buf = StringIO.new(data)
        loop do
          start_pos = buf.pos
          type = buf.read(1).unpack1("C")
          raise Raiha::TLS::Error, "unknown handshake type: #{type}" unless HANDSHAKE_TYPE.value?(type)

          hs = self.new
          hs.handshake_type = type
          hs.length = ("\x00" + buf.read(3)).unpack1("N")
          body = buf.read(hs.length)
          hs.message = Message.deserialize(data: body, type: hs.handshake_type)
          hs.raw_bytes = data[start_pos, 4 + hs.length]
          handshakes << hs

          break if buf.eof?
        end
        handshakes
      end
    end
  end
end

require_relative "handshake/message"
