# frozen_string_literal: true

module Raiha::Next::QUIC
  module Wire
    # A Version Negotiation packet (RFC 9000 "Version Negotiation Packet"):
    # a server's answer to a packet in a version it does not support, with
    # the version numbers it does. It belongs to no version, so its
    # connection IDs may have up to 255 bytes (RFC 8999), and it fills the
    # datagram.
    class VersionNegotiation < Data.define(:dcid, :scid, :versions)
      # The bit that is the fixed bit in version 1 is set, so that the
      # packet does not look like another protocol sharing the port; the
      # rest of the byte is unused.
      FIRST_BYTE = 0xc0
      INVARIANT_CONNECTION_ID_MAX_LENGTH = 255

      def initialize(dcid:, scid:, versions:)
        [dcid, scid].each do |cid|
          raise ArgumentError, "a connection ID has #{INVARIANT_CONNECTION_ID_MAX_LENGTH} bytes at most" if cid.bytesize > INVARIANT_CONNECTION_ID_MAX_LENGTH
        end
        raise ArgumentError, "a version is a 32-bit number" unless versions.all? { |version| version.between?(0, 0xffff_ffff) }
        super
      end

      # The rest of the packet after the Version field, from `reader`.
      def self.read(reader)
        dcid = reader.bytes(reader.u8)
        scid = reader.bytes(reader.u8)
        raise Malformed, "#{reader.remaining} bytes are no list of 4-byte versions" unless (reader.remaining % 4).zero?
        new(dcid:, scid:, versions: Array.new(reader.remaining / 4) { reader.u32 })
      end

      def encode
        writer = Writer.new.u8(FIRST_BYTE).u32(0).u8(dcid.bytesize).bytes(dcid).u8(scid.bytesize).bytes(scid)
        versions.each { |version| writer.u32(version) }
        writer.to_s
      end
    end
  end
end
