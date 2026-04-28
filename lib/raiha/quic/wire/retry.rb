# frozen_string_literal: true

require "openssl"
require_relative "../protocol/version"
require_relative "long_header"

module Raiha::Quic
  module Wire
    # RFC 9001 §5.8 Retry Packet integrity.
    #
    # A Retry packet authenticates the Original Destination Connection ID
    # via a 16-byte AEAD tag appended after the Retry Token. The tag is
    # computed with AEAD_AES_128_GCM over the "Retry Pseudo-Packet"
    # (ODCID length + ODCID + everything of the Retry packet before the
    # tag). Per-version key and nonce are fixed constants in the RFC so
    # any endpoint can verify the tag independently.
    module Retry
      INTEGRITY_TAG_LENGTH = 16

      # RFC 9001 §5.8 (QUIC v1) and RFC 9369 §3.3 (QUIC v2).
      INTEGRITY_KEY_V1 = ["be0c690b9f66575a1d766b54e368c84e"].pack("H*").freeze
      INTEGRITY_NONCE_V1 = ["461599d35d632bf2239825bb"].pack("H*").freeze
      INTEGRITY_KEY_V2 = ["8fb4b01b56ac48e260fbcbcead7ccc92"].pack("H*").freeze
      INTEGRITY_NONCE_V2 = ["d86969bc2d7c6d9990efb04a"].pack("H*").freeze

      # Build a complete Retry packet (RFC 9000 §17.2.5). Returns the
      # header bytes followed by the Retry Token and the 16-byte
      # Integrity Tag. There is no Length field — the token's length
      # is implicit from the datagram boundary, so the demuxer should
      # send the returned bytes as a standalone datagram.
      def self.build(source_connection_id:, destination_connection_id:, original_destination_connection_id:, retry_token:, version: Protocol::Version::V1)
        body = String.new(encoding: "BINARY")
        # Long header form (0x80) | fixed bit (0x40) | Retry type
        # (0b11 << 4 = 0x30). The low 4 bits are explicitly reserved
        # / unused per RFC §17.2.5; we leave them zero.
        body << [0xc0 | (LongHeader::PacketType::RETRY << 4)].pack("C")
        body << [version].pack("N")
        body << [destination_connection_id.bytesize].pack("C")
        body << destination_connection_id
        body << [source_connection_id.bytesize].pack("C")
        body << source_connection_id
        body << retry_token

        tag = compute_integrity_tag(
          original_destination_connection_id: original_destination_connection_id,
          retry_packet_without_tag: body,
          version: version
        )
        body + tag
      end

      # Compute the 16-byte Retry Integrity Tag for a Retry Pseudo-Packet.
      # `retry_packet_without_tag` is the bytes of the Retry packet from the
      # first header byte up to (but not including) the integrity tag.
      def self.compute_integrity_tag(original_destination_connection_id:, retry_packet_without_tag:, version: Protocol::Version::V1)
        key, nonce = integrity_key_and_nonce(version)

        pseudo = String.new(encoding: "BINARY")
        pseudo << [original_destination_connection_id.bytesize].pack("C")
        pseudo << original_destination_connection_id
        pseudo << retry_packet_without_tag

        cipher = OpenSSL::Cipher.new("aes-128-gcm")
        cipher.encrypt
        cipher.key = key
        cipher.iv = nonce
        cipher.auth_data = pseudo
        # No plaintext: the tag is computed over AAD alone.
        cipher.final
        cipher.auth_tag
      end

      # Verify the integrity tag attached to a Retry packet. Returns true
      # when `data` (the whole Retry packet including the 16-byte tag)
      # matches a tag computed from the given ODCID and version.
      def self.verify_integrity_tag(data:, original_destination_connection_id:, version: Protocol::Version::V1)
        return false if data.bytesize < INTEGRITY_TAG_LENGTH

        body = data.byteslice(0, data.bytesize - INTEGRITY_TAG_LENGTH) #: String
        received_tag = data.byteslice(-INTEGRITY_TAG_LENGTH, INTEGRITY_TAG_LENGTH) #: String
        expected_tag = compute_integrity_tag(
          original_destination_connection_id: original_destination_connection_id,
          retry_packet_without_tag: body,
          version: version
        )

        OpenSSL.fixed_length_secure_compare(expected_tag, received_tag)
      end

      def self.integrity_key_and_nonce(version)
        case version
        when Protocol::Version::V2
          [INTEGRITY_KEY_V2, INTEGRITY_NONCE_V2]
        else
          [INTEGRITY_KEY_V1, INTEGRITY_NONCE_V1]
        end
      end
    end
  end
end
