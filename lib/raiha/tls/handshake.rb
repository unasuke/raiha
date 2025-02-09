# frozen_string_literal: true

require "securerandom"
require "stringio"
require_relative "cipher_suite"

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

      def serialize
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
        raise "unknown handshake type: #{type}" unless HANDSHAKE_TYPE.value?(type)

        hs.handshake_type = type
        hs.length = ("\x00" + buf.read(3)).unpack1("N")
        body = buf.read
        return nil if body.bytesize != hs.length

        hs.message = Message.deserialize(data: body, type: hs.handshake_type)
        hs
      end

      def self.deserialize_multiple(data)
        handshakes = []
        buf = StringIO.new(data)
        loop do
          type = buf.read(1).unpack1("C")
          raise "unknown handshake type: #{type}" unless HANDSHAKE_TYPE.value?(type)

          hs = self.new
          hs.handshake_type = type
          hs.length = ("\x00" + buf.read(3)).unpack1("N")
          body = buf.read(hs.length)
          hs.message = Message.deserialize(data: body, type: hs.handshake_type)
          handshakes << hs

          break if buf.eof?
        end
        handshakes
      end
    end
  end
end

require_relative "handshake/message"
