# frozen_string_literal: true
require_relative "../protocol"

module Raiha::TLS::Protocol
  class Record
    CONTENT_TYPE = {
      invalid: 0,
      change_cipher_spec: 20,
      alert: 21,
      handshake: 22,
      application_data: 23,
    }.freeze
    LEGACY_PROTOCOL_VERSION = [0x03, 0x03].pack("C*") # TLS v1.2

    # @see https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
    class TLSPlaintext
      FRAGMENT_SIZE_LIMIT = 2**14
      attr_accessor :content_type
      attr_accessor :fragment

      def self.serialize(content)
        bufs = []
        data = content.serialize
        count = 0

        while (fragment = data[(FRAGMENT_SIZE_LIMIT*count)..(FRAGMENT_SIZE_LIMIT*(count+1)-1)])
          buf = String.new(encoding: "BINARY")
          case content
          when Handshake
            buf << [CONTENT_TYPE[:handshake]].pack("C")
          else
            raise "TODO #{content.class}"
          end
          buf << LEGACY_PROTOCOL_VERSION
          buf << [fragment.bytesize].pack("n")
          buf << fragment
          bufs << buf
          count += 1
        end
        bufs
      end
    end

    # @see https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
    class TLSCiphertext
      attr_accessor :tls_inner_plaintext

      def initialize
        @content_type = CONTENT_TYPE[:application_data]
        @protocol_version = [0x03, 0x03].pack("C*") # TLS v1.2

      end
      def serialize

      end
    end
  end
end
