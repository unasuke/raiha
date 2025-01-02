# frozen_string_literal: true

require "securerandom"
require "stringio"

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
        hs.message = Message.deserialize(data: buf.read(hs.length), type: hs.handshake_type)
        hs
      end
    end

    class CipherSuite
      TLS_AES_128_GCM_SHA256 = [0x13, 0x01]
      TLS_AES_256_GCM_SHA384 = [0x13, 0x02]
      TLS_CHACHA20_POLY1305_SHA256 = [0x13, 0x03]
      TLS_AES_128_CCM_SHA256 = [0x13, 0x04]
      TLS_AES_128_CCM_8_SHA256 = [0x13, 0x05]

      def initialize(cipher_name)
        raise "unknown cipher suite: #{cipher_name.inspect}" unless self.class.constants.include?(cipher_name)

        @name = cipher_name
      end

      def value
        self.class.const_get(@name)
      end

      def serialize
        value.pack("C*")
      end

      def self.deserialize(data)
        val = data.unpack("CC")
        self.new(self.constants.find { |c| self.const_get(c) == val })
      end
    end
  end
end

require_relative "handshake/message"
