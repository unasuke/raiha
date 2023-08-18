# frozen_string_literal: true

require "openssl"

module Raiha::Quic
  module Crypto
    # Remove or apply QUIC header protection
    # @see https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4
    # @todo Support to ChaCha20-Based Header Protection
    #   {https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.4}
    class HeaderProtection
      MASK = "\x00" * 31
      ZERO = "\x00" * 5
      PACKET_NUMBER_LENGTH_MAX = 4
      SAMPLE_LENGTH = 16

      # @param cipher_name [String] cipher name. Valid values are
      #   acceptable for +OpenSSL::Cipher.new+
      # @param key [String] key
      # @raise [RutimeError] If +cihper_name+ is invalid, raise it.
      def initialize(cipher_name:, key:)
        @cipher = OpenSSL::Cipher.new(cipher_name)
        @cipher.encrypt
        @cipher.key = key
        @mask = MASK.dup
      end

      # Apply packet protection
      # @see https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4
      # @param plain_header [IO::Buffer]
      # @param protected_payload [IO::Buffer]
      # @return [IO::Buffer] protected packet
      def apply(plain_header, protected_payload)
        packet_number_length = (plain_header.get_value(:U8, 0) & 0x03) + 1
        packet_number_offset = plain_header.size - packet_number_length
        @mask = mask(protected_payload.slice(PACKET_NUMBER_LENGTH_MAX - packet_number_length).slice(0, SAMPLE_LENGTH))

        buffer = IO::Buffer.for(plain_header.get_string + protected_payload.get_string).dup # make mutable
        if buffer.get_value(:U8, 0) & 0x80 != 0
          # buffer.set_value(:U8, 0, buffer.slice(0, 1).xor!(IO::Buffer.for((@mask[0].unpack1("C*") & 0x0f).chr)))
          buffer.copy(buffer.slice(0, 1).xor!(IO::Buffer.for((@mask[0].unpack1("C*") & 0x0f).chr)))
        else
          buffer.set_value(:U8, 0, buffer.slice(0, 1).xor!(IO::Buffer.for((@mask[0].unpack1("C*") & 0x1f)).chr))
        end
        buffer.copy(buffer.slice(packet_number_offset, packet_number_length).xor!(IO::Buffer.for(@mask[1..packet_number_length])), packet_number_offset)
        # packet_number_length.times do |i|
        #   buffer.set_value(:U8, )
        # end
        buffer
      end

      # Remove packet protection
      # @see https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4
      # @param packet [IO::Buffer]
      # @param encrypted_offset [Integer]
      # @return [Hash] +:plain_header+ and +:packet_number+
      def remove(packet, encrypted_offset)
        @mask = mask(packet.dup.slice(encrypted_offset + PACKET_NUMBER_LENGTH_MAX, SAMPLE_LENGTH))
        buffer = packet.dup.slice(0, encrypted_offset + PACKET_NUMBER_LENGTH_MAX)
        if buffer.get_value(:U8, 0) & 0x80 != 0
          # buffer.set_value(:U8, 0, buffer.slice(0, 1).xor!(IO::Buffer.for(@mask[0].unpack1("C*") & 0x0f)))
          buffer.copy(buffer.slice(0, 1).xor!(IO::Buffer.for((@mask[0].unpack1("C*") & 0x0f).chr)), 0)
        else
          # buffer.set_value(:U8, 0, buffer.slice(0, 1).xor!(IO::Buffer.for(@mask[0].unpack1("C*") & 0x1f)))
          buffer.copy(buffer.slice(0, 1).xor!(IO::Buffer.for((@mask[0].unpack1("C*") & 0x1f).chr)), 0)
        end
        packet_number_length = (buffer.get_value(:U8, 0) & 0x03) + 1
        packet_number_truncated = 0
        buffer.copy(buffer.slice(encrypted_offset, packet_number_length).xor!(IO::Buffer.for(@mask[1..packet_number_length])), encrypted_offset)
        packet_number_length.times do |i|
          packet_number_truncated = buffer.get_value(:U8, encrypted_offset + i) | (packet_number_truncated << 8)
        end

        { plain_header: buffer.slice(0, encrypted_offset + packet_number_length), packet_number: packet_number_truncated }
      end

      # @param sample [IO::Buffer]
      # @return [String]
      # @todo Support to ChaCha20-Based Header Protection
      #   {https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.4}
      private def mask(sample)
        @cipher.update(sample.get_string) + @cipher.final
      end
    end
  end
end
