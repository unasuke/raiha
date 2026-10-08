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
      #
      # A Version Negotiation packet comes back as VersionNegotiation, and a
      # long header packet in a version not supported as UnsupportedVersion.
      def self.parse(datagram, offset: 0, dcid_length:)
        reader = Reader.new(datagram, offset)
        first = reader.u8
        if first & 0x80 == 0
          raise Malformed, "the fixed bit is clear" if first & 0x40 == 0
          header = ShortHeader.new(dcid: reader.bytes(dcid_length), spin: first & 0x20 != 0, key_phase: nil)
          end_offset = datagram.bytesize
        else
          number = reader.u32
          # Version 0 is Version Negotiation, whatever the other bits say.
          return VersionNegotiation.read(reader) if number.zero?
          version = Version.find(number) or return UnsupportedVersion.read(number, reader)
          raise Malformed, "the fixed bit is clear" if first & 0x40 == 0
          header = long_header(reader, first, version)
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

      private_class_method def self.long_header(reader, first, version)
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
        # Takes header protection off with `header_protection`. The packet
        # number is decoded against `largest`, the largest one processed in
        # this packet number space (nil when none), and a short header gets
        # its key phase, which tells the keys for the payload.
        def unmask(header_protection, largest:)
          mask = header_protection.mask(datagram.byteslice(number_offset + SAMPLE_OFFSET, Crypto::HeaderProtection::SAMPLE_LENGTH))
          first = datagram.unpack1("C", offset:) ^ (mask.unpack1("C") & header.protected_bits)
          number_length = (first & 0x03) + 1
          header_length = number_offset - offset
          associated_data = datagram.byteslice(offset, header_length + number_length)
          associated_data.setbyte(0, first)
          truncated = 0
          number_length.times do |i|
            byte = associated_data.unpack1("C", offset: header_length + i) ^ mask.unpack1("C", offset: 1 + i)
            associated_data.setbyte(header_length + i, byte)
            truncated = (truncated << 8) | byte
          end
          Unmasked.new(
            header: header.unmasked(first),
            packet_number: PacketNumber.decode(truncated, length: number_length, largest:),
            reserved: first & header.reserved_bits,
            associated_data:,
            ciphertext: datagram.byteslice(number_offset + number_length, end_offset - number_offset - number_length)
          )
        end
      end

      # A packet with header protection off and the payload still sealed:
      # the header, the packet number, the value of the reserved bits, the
      # header as the AEAD's associated data, and the ciphertext.
      class Unmasked < Data.define(:header, :packet_number, :reserved, :associated_data, :ciphertext)
        # The payload, or nil when `aead` does not open it, which is not an
        # error: the packet is dropped. A packet that opens with reserved
        # bits other than zero is a protocol violation (RFC 9000 "Long Header
        # Packets", "Short Header Packets").
        def open(aead)
          payload = aead.open(packet_number:, header: associated_data, ciphertext:) or return nil
          raise Malformed.new("the reserved bits are #{reserved}", code: ErrorCode::PROTOCOL_VIOLATION) unless reserved.zero?
          payload
        end
      end
    end
  end
end
