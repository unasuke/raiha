# frozen_string_literal: true

module Raiha::Next::QUIC
  module Crypto
    # The packet protection of one key (RFC 9001 "AEAD Usage"): the nonce is
    # the IV with the packet number XORed into its low bytes, and the header
    # up to the end of the packet number is the associated data. Each
    # direction keeps its own OpenSSL context, keyed once and reused for
    # every packet.
    class AEAD
      CIPHERS = { aes_128_gcm: "aes-128-gcm", aes_256_gcm: "aes-256-gcm", chacha20_poly1305: "chacha20-poly1305" }.freeze #: Hash[Symbol, String]

      def initialize(suite:, key:, iv:)
        raise ArgumentError, "#{suite.name} takes a #{suite.key_length}-byte key" unless key.bytesize == suite.key_length
        raise ArgumentError, "#{suite.name} takes a #{suite.iv_length}-byte IV" unless iv.bytesize == suite.iv_length
        @name = CIPHERS.fetch(suite.aead)
        @tag_length = suite.tag_length
        @key = key.b
        # A packet number has 62 bits at most, so it reaches only the low 8
        # of the 12 bytes.
        @iv_high = iv.unpack1("N")
        @iv_low = iv.unpack1("Q>", offset: 4)
        @sealer = nil #: OpenSSL::Cipher?
        @opener = nil #: OpenSSL::Cipher?
      end

      # The ciphertext followed by the tag.
      def seal(packet_number:, header:, plaintext:)
        cipher = @sealer ||= context(:encrypt)
        cipher.iv = nonce(packet_number)
        cipher.auth_data = header
        sealed = plaintext.empty? ? "".b : cipher.update(plaintext)
        sealed << cipher.final << cipher.auth_tag(@tag_length)
      end

      # The plaintext, or nil when `ciphertext` (with its tag) does not
      # authenticate. A forged packet, or one under another key, is an
      # everyday event and not an exception; any other failure of OpenSSL is
      # a bug of ours and raises.
      def open(packet_number:, header:, ciphertext:)
        body_length = ciphertext.bytesize - @tag_length
        return nil if body_length.negative?
        cipher = @opener ||= context(:decrypt)
        cipher.iv = nonce(packet_number)
        cipher.auth_tag = ciphertext.byteslice(body_length, @tag_length)
        cipher.auth_data = header
        opened = body_length.zero? ? "".b : cipher.update(ciphertext.byteslice(0, body_length))
        opened << cipher.final
      rescue OpenSSL::Cipher::AuthTagError
        nil
      end

      private def instance_variables_to_inspect = %i[@name]

      private def nonce(packet_number) = [@iv_high, @iv_low ^ packet_number].pack("NQ>")

      private def context(direction)
        cipher = OpenSSL::Cipher.new(@name)
        direction == :encrypt ? cipher.encrypt : cipher.decrypt
        cipher.key = @key
        cipher
      end
    end
  end
end
