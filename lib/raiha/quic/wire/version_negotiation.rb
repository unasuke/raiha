# frozen_string_literal: true

require_relative "../protocol/version"

module Raiha::Quic
  module Wire
    # RFC 9000 §6, §17.2.1 Version Negotiation Packet.
    #
    # A Version Negotiation packet is a long-header packet with the Version
    # field set to 0x00000000. It is always sent in response to a packet
    # whose version the server does not support, and carries the list of
    # versions the server does support so the client can pick one and
    # restart the handshake.
    #
    # The Fixed Bit is NOT set in a Version Negotiation packet, so the usual
    # packet-validation path (which requires Fixed Bit = 1) correctly
    # discards it; callers must check for the VN pattern explicitly before
    # running the normal packet processor.
    module VersionNegotiation
      VERSION_FIELD_OFFSET = 1
      VERSION_FIELD_LENGTH = 4

      # True when `data` is shaped like a Version Negotiation packet: long
      # header form (bit 7 of first byte is 1) and the 32-bit Version field
      # is all zero.
      def self.match?(data)
        return false if data.bytesize < VERSION_FIELD_OFFSET + VERSION_FIELD_LENGTH
        return false if (data.getbyte(0) & 0x80) == 0

        version_bytes = data.byteslice(VERSION_FIELD_OFFSET, VERSION_FIELD_LENGTH) #: String
        version_bytes.unpack1("N") == 0
      end

      # Build a Version Negotiation packet. Connection IDs are byte strings
      # (same shape as the wire serialization). Returns the encoded packet.
      def self.build(src_connection_id:, dest_connection_id:, supported_versions:)
        buf = String.new(encoding: "BINARY")

        # First byte: long header form (bit 7 = 1). RFC §17.2.1: all other
        # bits are "unused" and set arbitrarily. Clear the Fixed Bit so the
        # packet is unambiguously a VN.
        buf << [0x80].pack("C")
        buf << [0x00000000].pack("N")          # Version = 0 identifies VN.
        buf << [dest_connection_id.bytesize].pack("C")
        buf << dest_connection_id
        buf << [src_connection_id.bytesize].pack("C")
        buf << src_connection_id
        supported_versions.each { |v| buf << [v].pack("N") }

        buf
      end

      # Parse a Version Negotiation packet. Returns
      # `{ dest_connection_id:, src_connection_id:, supported_versions: }`
      # or nil if the shape is invalid.
      def self.parse(data)
        return nil unless match?(data)

        pos = 1 + VERSION_FIELD_LENGTH
        dcid_length = data.getbyte(pos)
        return nil if dcid_length.nil?
        pos += 1
        return nil if data.bytesize < pos + dcid_length

        dcid = data.byteslice(pos, dcid_length) #: String
        pos += dcid_length

        scid_length = data.getbyte(pos)
        return nil if scid_length.nil?
        pos += 1
        return nil if data.bytesize < pos + scid_length

        scid = data.byteslice(pos, scid_length) #: String
        pos += scid_length

        remaining = data.bytesize - pos
        return nil unless remaining.positive? && (remaining % 4).zero?

        versions = [] #: Array[Integer]
        (remaining / 4).times do |i|
          bytes = data.byteslice(pos + i * 4, 4) #: String
          version = bytes.unpack1("N") #: Integer
          versions << version
        end

        {
          dest_connection_id: dcid,
          src_connection_id: scid,
          supported_versions: versions,
        }
      end
    end
  end
end
