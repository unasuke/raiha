# frozen_string_literal: true

module Raiha::QUIC
  module Wire
    # In QUIC version 1 a connection ID has 20 bytes at most (RFC 9000 "Long
    # Header Packets").
    CONNECTION_ID_MAX_LENGTH = 20
    EMPTY = "".b.freeze

    # The header of an Initial, 0-RTT or Handshake packet (RFC 9000 "Long
    # Header Packets"), apart from the packet number. `token` is empty
    # except in an Initial packet. Retry has a header of its own.
    class LongHeader < Data.define(:type, :version, :dcid, :scid, :token)
      TYPES = %i[initial zero_rtt handshake].freeze
      # The bits of the first byte under header protection: the two reserved
      # bits and the packet number length.
      PROTECTED_BITS = 0x0f
      RESERVED_BITS = 0x0c

      def initialize(type:, version:, dcid:, scid:, token: EMPTY)
        raise ArgumentError, "a long header with a packet number is one of #{TYPES}, not #{type.inspect}" unless TYPES.include?(type)
        raise ArgumentError, "only an Initial packet carries a token" unless type == :initial || token.empty?
        [dcid, scid].each do |cid|
          raise ArgumentError, "a connection ID has #{CONNECTION_ID_MAX_LENGTH} bytes at most, not #{cid.bytesize}" if cid.bytesize > CONNECTION_ID_MAX_LENGTH
        end
        super
      end

      def protected_bits = PROTECTED_BITS

      def reserved_bits = RESERVED_BITS

      # The first byte before header protection.
      def first_byte(packet_number_length) = 0xc0 | (version.type_bits(type) << 4) | (packet_number_length - 1)

      # Writes what comes between the first byte and the packet number.
      # `length` is the value of the Length field: the bytes of the packet
      # number, the payload and the tag.
      def write_fields(writer, length:)
        writer.u32(version.number).u8(dcid.bytesize).bytes(dcid).u8(scid.bytesize).bytes(scid)
        writer.varint(token.bytesize).bytes(token) if type == :initial
        writer.varint(length)
      end

      # This header with header protection off: none of its fields was
      # under it.
      def unmasked(_first_byte) = self
    end

    # The header of a 1-RTT packet (RFC 9000 "Short Header Packets"), apart
    # from the packet number. The Destination Connection ID goes without its
    # length: the receiver knows the length of the IDs it issued. The key
    # phase is under header protection, so a parsed header has nil there
    # until the protection is off.
    class ShortHeader < Data.define(:dcid, :spin, :key_phase)
      # The two reserved bits, the key phase and the packet number length.
      PROTECTED_BITS = 0x1f
      RESERVED_BITS = 0x18

      def initialize(dcid:, spin: false, key_phase: 0)
        raise ArgumentError, "a connection ID has #{CONNECTION_ID_MAX_LENGTH} bytes at most, not #{dcid.bytesize}" if dcid.bytesize > CONNECTION_ID_MAX_LENGTH
        super
      end

      # The packet type, as `LongHeader#type` tells it for a long header.
      def type = :one_rtt

      def protected_bits = PROTECTED_BITS

      def reserved_bits = RESERVED_BITS

      # The first byte before header protection.
      def first_byte(packet_number_length)
        key_phase_bit = case key_phase
          when 0 then 0x00
          when 1 then 0x04
          else raise ArgumentError, "the key phase is 0 or 1, not #{key_phase.inspect}"
          end
        0x40 | (spin ? 0x20 : 0) | key_phase_bit | (packet_number_length - 1)
      end

      # Writes what comes between the first byte and the packet number.
      def write_fields(writer, length:) = writer.bytes(dcid)

      # This header with header protection off, which reveals the key phase
      # in `first_byte`.
      def unmasked(first_byte) = with(key_phase: (first_byte >> 2) & 1)
    end
  end
end
