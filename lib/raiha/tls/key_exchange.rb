# frozen_string_literal: true

require_relative "crypto"
require_relative "masked_inspect"

module Raiha::TLS
  # Key exchange in the shape of a KEM, since that is what RFC 9846 now
  # describes and what the post-quantum hybrids are: the client sends a
  # public key, the server encapsulates to it and returns a ciphertext. For
  # ECDH the server's "ciphertext" is its own fresh public key.
  #
  # A provider answers `supported_groups`, `generate(group)`,
  # `encapsulate(group, peer_public_bytes)` and `decapsulate(key_pair,
  # ciphertext)`. It must generate a fresh key pair for every connection:
  # RFC 9846 forbids reusing a key share, although a peer that does so must
  # still be accepted, as RFC 8446 allowed it. `encapsulate` and
  # `decapsulate` return nil for bytes from the peer that are not a valid key
  # of the group; the state machine answers with illegal_parameter.
  module KeyExchange
    class KeyPair < Data.define(:group, :public_bytes, :private_key)
      include MaskedInspect

      def masked_members = %i[private_key]
    end

    # The default provider, on OpenSSL through Crypto::ECDH: X25519 first,
    # then P-256 and P-384.
    class OpenSSL
      GROUPS = Crypto::ECDH.groups.freeze #: Array[Symbol]

      def supported_groups = GROUPS

      def generate(group)
        check_group(group)
        key = Crypto::ECDH.generate(group)
        KeyPair.new(group:, public_bytes: Crypto::ECDH.public_bytes(group, key).freeze, private_key: key)
      end

      # A fresh key pair of our own, whose public key is the ciphertext, and
      # the shared secret; nil when the peer's key is invalid.
      def encapsulate(group, peer_public_bytes)
        key_pair = generate(group)
        shared_secret = decapsulate(key_pair, peer_public_bytes) or return nil
        [key_pair.public_bytes, shared_secret]
      end

      def decapsulate(key_pair, ciphertext)
        shared_secret = Crypto::ECDH.derive(key_pair.group, key_pair.private_key, ciphertext)
        return nil if shared_secret.nil? || shared_secret.each_byte.all?(&:zero?)
        shared_secret
      end

      private def check_group(group)
        raise ArgumentError, "unsupported group: #{group.inspect}" unless GROUPS.include?(group)
      end
    end
  end
end
