# frozen_string_literal: true

module Raiha::Next::QUIC
  module Wire
    # A Retry packet (RFC 9000 "Retry Packet") and its integrity tag (RFC
    # 9001 "Retry Packet Integrity"): AES-128-GCM under the version's fixed
    # key and nonce over no plaintext, with the packet prefixed by the
    # Destination Connection ID of the client's Initial as associated data.
    # Only who saw that Initial can make a Retry the client takes.
    #
    # A Retry built to be sent has no tag until `seal` computes it.
    class Retry < Data.define(:version, :dcid, :scid, :token, :unused, :tag)
      TAG_LENGTH = 16
      # The four low bits of the first byte are unused and arbitrary. These
      # are set, as in RFC 9001 appendix A.4.
      UNUSED = 0x0f

      def initialize(version:, dcid:, scid:, token:, unused: UNUSED, tag: nil)
        [dcid, scid].each do |cid|
          raise ArgumentError, "a connection ID has #{CONNECTION_ID_MAX_LENGTH} bytes at most, not #{cid.bytesize}" if cid.bytesize > CONNECTION_ID_MAX_LENGTH
        end
        raise ArgumentError, "a Retry carries a token" if token.empty?
        raise ArgumentError, "the unused bits are four, not #{unused}" unless unused.between?(0, 0x0f)
        super
      end

      # The packet, with the tag for an Initial whose Destination
      # Connection ID was `original_dcid`.
      def seal(original_dcid) = body + integrity.seal(packet_number: 0, header: pseudo_packet(original_dcid), plaintext: EMPTY)

      # The packet up to the tag.
      private def body
        Writer.new.u8(0xc0 | (version.type_bits(:retry) << 4) | unused).u32(version.number)
          .u8(dcid.bytesize).bytes(dcid).u8(scid.bytesize).bytes(scid).bytes(token).to_s
      end

      # The Retry Pseudo-Packet: what the tag covers.
      private def pseudo_packet(original_dcid) = Writer.new.u8(original_dcid.bytesize).bytes(original_dcid).bytes(body).to_s

      private def integrity
        Crypto::AEAD.new(suite: Raiha::Next::TLS::CipherSuite::TLS_AES_128_GCM_SHA256, key: version.retry_key, iv: version.retry_nonce)
      end
    end
  end
end
