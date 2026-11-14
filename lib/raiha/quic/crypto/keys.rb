# frozen_string_literal: true

module Raiha::QUIC
  module Crypto
    # The packet protection of one direction at one encryption level, from
    # its secret (RFC 9001 "Packet Protection Keys"): the AEAD key and IV
    # and the header protection key, under the labels of `version`.
    class Keys < Data.define(:aead, :header_protection)
      def self.derive(suite:, secret:, version:)
        hp = Raiha::TLS::KeySchedule.expand_label(secret:, label: version.label("hp"), length: suite.key_length, hash: suite.hash_algorithm)
        new(aead: derive_aead(suite:, secret:, version:), header_protection: HeaderProtection.new(suite:, key: hp))
      end

      def self.derive_aead(suite:, secret:, version:)
        hash = suite.hash_algorithm
        key = Raiha::TLS::KeySchedule.expand_label(secret:, label: version.label("key"), length: suite.key_length, hash:)
        iv = Raiha::TLS::KeySchedule.expand_label(secret:, label: version.label("iv"), length: suite.iv_length, hash:)
        AEAD.new(suite:, key:, iv:)
      end

      # The 1-RTT secret after `secret` (RFC 9001 "Initiating a Key
      # Update").
      def self.next_secret(suite:, secret:, version:)
        Raiha::TLS::KeySchedule.expand_label(secret:, label: version.label("ku"), length: suite.hash_length, hash: suite.hash_algorithm)
      end

      # These keys after a key update to `secret`: the AEAD key and IV from
      # it, the header protection key as it was.
      def update(suite:, secret:, version:) = with(aead: Keys.derive_aead(suite:, secret:, version:))
    end
  end
end
