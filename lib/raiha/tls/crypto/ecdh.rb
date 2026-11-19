# frozen_string_literal: true

module Raiha::TLS
  module Crypto
    # Elliptic-curve Diffie-Hellman over the groups TLS 1.3 uses, with public
    # keys as they appear in key_share: the 32-byte u-coordinate for X25519
    # and the uncompressed point for the NIST curves.
    module ECDH
      CURVES = { secp256r1: "prime256v1", secp384r1: "secp384r1" }.freeze #: Hash[Symbol, String]
      POINT_LENGTHS = { secp256r1: 65, secp384r1: 97 }.freeze #: Hash[Symbol, Integer]
      X25519_LENGTH = 32

      def self.groups = [:x25519, *CURVES.keys]

      def self.generate(group)
        if group == :x25519
          OpenSSL::PKey.generate_key("X25519")
        else
          OpenSSL::PKey::EC.generate(curve_name(group))
        end
      end

      # A private key from its raw bytes: the scalar for the NIST curves.
      # Only fixed test keys need this. The ECPrivateKey carries the public
      # key too, the scalar times the generator: OpenSSL works it out where
      # it is missing, but LibreSSL refuses such a key.
      def self.private_key(group, bytes)
        return OpenSSL::PKey.new_raw_private_key("X25519", bytes) if group == :x25519
        name = curve_name(group)
        point = OpenSSL::PKey::EC::Group.new(name).generator.mul(OpenSSL::BN.new(bytes, 2)) # steep:ignore
        der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(1), OpenSSL::ASN1::OctetString(bytes),
          explicit(OpenSSL::ASN1::ObjectId(name), 0), explicit(OpenSSL::ASN1::BitString(point.to_octet_string(:uncompressed)), 1)]).to_der
        OpenSSL::PKey::EC.new(der)
      end

      # `value` under the context-specific tag `tag`, EXPLICIT.
      private_class_method def self.explicit(value, tag)
        value.tag = tag
        value.tagging = :EXPLICIT
        value.tag_class = :CONTEXT_SPECIFIC
        value
      end

      def self.public_bytes(group, key)
        if group == :x25519
          key.raw_public_key
        else
          key.public_key.to_octet_string(:uncompressed) # steep:ignore
        end
      end

      # The shared secret, or nil when the peer's public key is not a valid
      # key of the group: a wrong length, a compressed or off-curve point, or
      # an X25519 key that yields the all-zero secret, which OpenSSL refuses.
      def self.derive(group, key, peer_public_bytes)
        if group == :x25519
          return nil unless peer_public_bytes.bytesize == X25519_LENGTH
          key.derive(OpenSSL::PKey.new_raw_public_key("X25519", peer_public_bytes))
        else
          return nil unless peer_public_bytes.bytesize == POINT_LENGTHS.fetch(group) && peer_public_bytes.getbyte(0) == 4
          ec_group = OpenSSL::PKey::EC::Group.new(curve_name(group))
          point = OpenSSL::PKey::EC::Point.new(ec_group, OpenSSL::BN.new(peer_public_bytes, 2))
          key.dh_compute_key(point) # steep:ignore
        end
      rescue OpenSSL::PKey::PKeyError, OpenSSL::PKey::EC::Point::Error
        nil
      end

      private_class_method def self.curve_name(group)
        CURVES.fetch(group) { raise ArgumentError, "unsupported group: #{group.inspect}" }
      end
    end
  end
end
