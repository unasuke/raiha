# frozen_string_literal: true

module Raiha::Next::QUIC
  module Wire
    # A packet with a packet number under packet protection (RFC 9001
    # "Packet Protection"): the payload sealed by the AEAD with the header
    # up to the packet number as associated data, then header protection
    # over the low bits of the first byte and the packet number, with a
    # mask from a sample of the ciphertext.
    module Packet
      # The sample starts this many bytes into the packet number, as if
      # the packet number were always 4 bytes long.
      SAMPLE_OFFSET = 4

      # The packet with `header`, `packet_number` in `packet_number_length`
      # bytes, and `payload` (frames, padded already), protected by `keys`.
      def self.seal(header, packet_number:, packet_number_length:, payload:, keys:)
        encoded_number = PacketNumber.encode(packet_number, packet_number_length)
        if packet_number_length + payload.bytesize < SAMPLE_OFFSET
          raise ArgumentError, "#{payload.bytesize} bytes of payload after a #{packet_number_length}-byte packet number leave no room for the sample"
        end
        writer = Writer.new.u8(header.first_byte(packet_number_length))
        header.write_fields(writer, length: packet_number_length + payload.bytesize + keys.aead.tag_length)
        number_offset = writer.bytesize
        packet = writer.bytes(encoded_number).to_s
        sealed = keys.aead.seal(packet_number:, header: packet, plaintext: payload)
        mask = keys.header_protection.mask(sealed.byteslice(SAMPLE_OFFSET - packet_number_length, Crypto::HeaderProtection::SAMPLE_LENGTH))
        packet.setbyte(0, packet.unpack1("C") ^ (mask.unpack1("C") & header.protected_bits))
        packet_number_length.times do |i|
          packet.setbyte(number_offset + i, packet.unpack1("C", offset: number_offset + i) ^ mask.unpack1("C", offset: 1 + i))
        end
        packet << sealed
      end
    end
  end
end
