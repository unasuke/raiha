# frozen_string_literal: true

require_relative "../codec"
require_relative "../signature_scheme"
require_relative "message"
require_relative "violation"

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

      # RFC 9846 forbids RSASSA-PKCS1-v1_5 and SHA-1 in CertificateVerify. A
      # scheme this implementation does not define is left to the state
      # machine, which rejects any scheme it did not offer.
      def validate
        scheme = SignatureScheme.find(algorithm)
        return nil if scheme.nil? || scheme.usable_in_certificate_verify?
        Violation.new(alert: :illegal_parameter, reason: :signature_algorithm)
      end

      def write_body(w)
        w.u16(algorithm)
        w.vector(2, max: 0xffff) { w.bytes(signature) }
      end
    end
  end
end
