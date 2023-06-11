# frozen_string_literal: true

require "openssl"

module Raiha::Quic
  module Crypto
    class HeaderProtection
      MASK = "\x00" * 31
      ZERO = "\x00" * 5

      # @param cipher_name [String] cipher name. Valid values are
      #   acceptable for +OpenSSL::Cipher.new+
      # @param key [String] key
      def initialize(cipher_name:, key:)
        @cipher = OpenSSL::Cipher.new(cipher_name)
        @mask = MASK
      end

      # @param plain_header [IO::Buffer]
      # @param protected_payload [IO::Buffer]
      def apply(plain_header, protected_payload)

      end

      # @param packet [IO::Buffer]
      # @param encrypted_offset [IO::Buffer]
      def remove(packet, encrypted_oooset)
        mask(packet.slice)
      end

      # @param sample [IO::Buffer]
      private def mask(sample)
        @mask = @cipher.update(sample.get_string) + @cipher.final
      end
    end
  end
end
