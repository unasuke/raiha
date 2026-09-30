# frozen_string_literal: true

require_relative "../codec"
require_relative "message"
require_relative "violation"

module Raiha::Next::TLS
  module Handshake
    class CertificateVerify < Data.define(:algorithm, :signature)
      include Message

      MSG_TYPE = 15

      # RFC 9846 forbids RSASSA-PKCS1-v1_5 and SHA-1 in CertificateVerify:
      # rsa_pkcs1_sha1, dsa_sha1_RESERVED, ecdsa_sha1, rsa_pkcs1_sha256,
      # rsa_pkcs1_sha384 and rsa_pkcs1_sha512.
      FORBIDDEN_ALGORITHMS = [0x0201, 0x0202, 0x0203, 0x0401, 0x0501, 0x0601].freeze

      def self.parse_body(body, registry: nil)
        r = Codec::Reader.new(body)
        algorithm = r.u16
        signature = r.opaque(2, max: 0xffff)
        r.finish!
        new(algorithm:, signature:)
      end

      def msg_type = MSG_TYPE

      def validate
        return nil unless FORBIDDEN_ALGORITHMS.include?(algorithm)
        Violation.new(alert: :illegal_parameter, reason: :signature_algorithm)
      end

      def write_body(w)
        w.u16(algorithm)
        w.vector(2, max: 0xffff) { w.bytes(signature) }
      end
    end
  end
end
