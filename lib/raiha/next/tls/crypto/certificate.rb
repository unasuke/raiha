# frozen_string_literal: true

module Raiha::Next::TLS
  module Crypto
    # X.509 certificates from DER.
    module Certificate
      # nil for bytes that are not one DER certificate.
      def self.parse(der)
        OpenSSL::X509::Certificate.new(der)
      rescue OpenSSL::X509::CertificateError
        nil
      end
    end
  end
end
