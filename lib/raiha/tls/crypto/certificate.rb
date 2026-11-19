# frozen_string_literal: true

module Raiha::TLS
  module Crypto
    # X.509 certificates from DER.
    module Certificate
      # The SignatureScheme code point of a certificate's own signature, by
      # the name of its algorithm in lower case; nil for one without a
      # matching scheme (RSASSA-PSS parameters, for one, are not looked
      # into). Lower case, since the libraries differ in case: OpenSSL says
      # "ED25519" where LibreSSL says "Ed25519".
      SIGNATURE_SCHEMES = {
        "sha256WithRSAEncryption" => 0x0401, "sha384WithRSAEncryption" => 0x0501, "sha512WithRSAEncryption" => 0x0601,
        "ecdsa-with-SHA256" => 0x0403, "ecdsa-with-SHA384" => 0x0503, "ecdsa-with-SHA512" => 0x0603,
        "ED25519" => 0x0807, "ED448" => 0x0808, "sha1WithRSAEncryption" => 0x0201, "ecdsa-with-SHA1" => 0x0203
      }.transform_keys(&:downcase).freeze #: Hash[String, Integer]

      def self.signature_scheme_id(certificate) = SIGNATURE_SCHEMES[certificate.signature_algorithm.downcase]

      # nil for bytes that are not one DER certificate.
      def self.parse(der)
        OpenSSL::X509::Certificate.new(der)
      rescue OpenSSL::X509::CertificateError
        nil
      end
    end
  end
end
