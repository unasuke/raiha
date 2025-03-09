# frozen_string_literal: true

require "openssl"

module Raiha
  module TLS
    # @see https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.1
    class TranscriptHash < Hash
      def digest_algorithm=(algorithm)
        @digest = OpenSSL::Digest.new(algorithm)
      end

      def hash
        @digest.reset
        values_for_hash.each { |value| @digest.update(value) }
        @digest.digest
      end

      private def values_for_hash
        # TODO: hello_retry_request
        %i(
          client_hello
          server_hello
          encrypted_extensions
          certificate
          certificate_request
          certificate_verify
          finished
        ).map { |key| self[key] }.compact
      end
    end
  end
end
