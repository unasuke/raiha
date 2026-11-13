# frozen_string_literal: true

require_relative "../codec"
require_relative "../extension"
require_relative "message"
require_relative "violation"

module Raiha::Next::TLS
  module Handshake
    class CertificateRequest < Data.define(:certificate_request_context, :extensions)
      include Message
      include ExtensionLookup

      MSG_TYPE = 13

      def self.parse_body(body, registry:)
        r = Codec::Reader.new(body)
        certificate_request_context = r.opaque(1, max: 0xff)
        extensions = Extension.read_list(r, context: :certificate_request, registry:)
        r.finish!
        new(certificate_request_context:, extensions:)
      end

      def msg_type = MSG_TYPE

      def validate
        case extension(Extension::SignatureAlgorithms::TYPE)
        when Extension::SignatureAlgorithms then nil
        else Violation.new(alert: :missing_extension, reason: :signature_algorithms)
        end
      end

      def write_body(w)
        w.vector(1, max: 0xff) { w.bytes(certificate_request_context) }
        Extension.write_list(w, extensions)
      end
    end
  end
end
