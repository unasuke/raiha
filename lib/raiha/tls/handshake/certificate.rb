# frozen_string_literal: true

require_relative "../codec"
require_relative "../extension"
require_relative "message"
require_relative "violation"

module Raiha::TLS
  module Handshake
    # One certificate in a Certificate message. Only X.509 is supported, so
    # cert_data is a DER certificate. Its extensions have a context of their
    # own: status_request and signed_certificate_timestamp may appear here.
    class CertificateEntry < Data.define(:cert_data, :extensions)
      include ExtensionLookup

      def self.read(r, registry:)
        cert_data = r.opaque(3, min: 1, max: 0xffffff)
        new(cert_data:, extensions: Extension.read_list(r, context: :certificate_entry, registry:))
      end

      def write(w)
        w.vector(3, min: 1, max: 0xffffff) { w.bytes(cert_data) }
        Extension.write_list(w, extensions)
      end
    end

    class Certificate < Data.define(:certificate_request_context, :certificate_list)
      include Message

      MSG_TYPE = 11

      def self.parse_body(body, registry:)
        r = Codec::Reader.new(body)
        certificate_request_context = r.opaque(1, max: 0xff)
        certificate_list = r.vector(3, max: 0xffffff) do |v|
          # @type var list: Array[CertificateEntry]
          list = []
          list << CertificateEntry.read(v, registry:) until v.eof?
          list.freeze
        end
        r.finish!
        new(certificate_request_context:, certificate_list:)
      end

      def msg_type = MSG_TYPE

      # Nothing to check without context.
      def validate = nil

      def write_body(w)
        w.vector(1, max: 0xff) { w.bytes(certificate_request_context) }
        w.vector(3, max: 0xffffff) { certificate_list.each { |entry| entry.write(w) } }
      end
    end
  end
end
