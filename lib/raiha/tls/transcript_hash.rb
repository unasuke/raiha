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

      def empty_digest
        @digest.reset
        @digest.digest
      end

      # RFC 8446 Section 4.4.1
      # Replace the original ClientHello with a synthetic message_hash construct
      # for HelloRetryRequest transcript hash calculation.
      def replace_client_hello_with_message_hash
        original_ch = self[:client_hello]
        @digest.reset
        hash_of_ch1 = @digest.update(original_ch).digest

        length_bytes = [hash_of_ch1.bytesize].pack("N").byteslice(1..) # uint24
        self[:client_hello] = "\xfe" + length_bytes + hash_of_ch1
      end

      private def values_for_hash
        keys = %i(client_hello server_hello)
        keys << :client_hello_retry if self[:client_hello_retry]
        keys.concat %i(
          encrypted_extensions
          certificate
          certificate_request
          certificate_verify
          finished
        )
        keys.map { |key| self[key] }.compact
      end
    end
  end
end
