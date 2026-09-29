# frozen_string_literal: true

require_relative "../codec"
require_relative "message"

module Raiha::Next::TLS
  module Handshake
    class CertificateVerify < Data.define(:algorithm, :signature)
      include Message

      MSG_TYPE = 15

      def self.parse_body(body, registry: nil)
        r = Codec::Reader.new(body)
        algorithm = r.u16
        signature = r.opaque(2, max: 0xffff)
        r.finish!
        new(algorithm:, signature:)
      end

      def msg_type = MSG_TYPE

      def write_body(w)
        w.u16(algorithm)
        w.vector(2, max: 0xffff) { w.bytes(signature) }
      end
    end
  end
end
