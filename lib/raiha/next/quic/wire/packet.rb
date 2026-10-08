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

      # The packet at `offset` in `datagram`, as far as it reads with its
      # protection on: the header, where the packet number starts, and where
      # the packet ends, which is where a packet coalesced after it starts.
      # A short header packet runs to the end of the datagram, and its
      # connection ID is `dcid_length` bytes. Bytes that do not make such a
      # packet raise Malformed, and the packet is to be dropped.
      def self.parse(datagram, offset: 0, dcid_length:)
        reader = Reader.new(datagram, offset)
        first = reader.u8
        raise Malformed, "the fixed bit is clear" if first & 0x40 == 0
        if first & 0x80 == 0
          header = ShortHeader.new(dcid: reader.bytes(dcid_length), spin: first & 0x20 != 0, key_phase: nil)
          end_offset = datagram.bytesize
        else
          header = long_header(reader, first)
          length = reader.varint
          raise Truncated, "the Length field says #{length} bytes, #{reader.remaining} are left" if length > reader.remaining
          end_offset = reader.offset + length
        end
        number_offset = reader.offset
        if end_offset - number_offset < SAMPLE_OFFSET + Crypto::HeaderProtection::SAMPLE_LENGTH
          raise Malformed, "#{end_offset - number_offset} bytes after the header are too few for a sample"
        end
        Parsed.new(header:, datagram:, offset:, number_offset:, end_offset:)
      end

      private_class_method def self.long_header(reader, first)
        number = reader.u32
        version = Version.find(number) or raise Malformed, format("version 0x%08x is not supported", number)
        dcid = connection_id(reader)
        scid = connection_id(reader)
        case type = version.packet_type((first >> 4) & 0x03)
        when :retry then raise Malformed, "a Retry packet carries no packet number"
        else LongHeader.new(type:, version:, dcid:, scid:, token: type == :initial ? reader.bytes(reader.varint) : EMPTY)
        end
      end

      private_class_method def self.connection_id(reader)
        length = reader.u8
        raise Malformed, "a connection ID of #{length} bytes" if length > CONNECTION_ID_MAX_LENGTH
        reader.bytes(length)
      end

      # A packet as `parse` read it, both protections still on: `header`
      # (a short header without its key phase yet), and where in `datagram`
      # the packet starts, its packet number starts, and it ends.
      class Parsed < Data.define(:header, :datagram, :offset, :number_offset, :end_offset)
      end
    end
  end
end
