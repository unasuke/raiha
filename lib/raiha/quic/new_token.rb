# frozen_string_literal: true

require "ipaddr"

module Raiha::QUIC
  # The token of a NEW_TOKEN frame (RFC 9000 "Address Validation for Future
  # Connections"), which a client puts in the Initial of a later connection
  # to show it receives at the address it sends from:
  #
  #   kind (1, a NEW_TOKEN token) || nonce (12, random)
  #   || AES-256-GCM(QUIC version (4) || expiry (8, seconds since the epoch))
  #
  # with the kind and the client's IP address, its bytes without the port,
  # as the associated data. The nonce makes every token one of its own;
  # the version, which RFC 9369 "TLS Resumption and NEW_TOKEN Tokens" asks
  # to check, and the expiry are sealed, so that nothing of the connection
  # it came on shows. The key comes from the Endpoint's retry_token_key, by
  # a label of its own. No token is recorded as used: the address and the
  # expiry limit replays, and a token from the same address may be taken
  # again until it expires.
  module NewToken
    KIND = 1
    LIFETIME = 86_400
    NONCE_LENGTH = 12
    # kind, nonce, version, expiry and the tag.
    LENGTH = 1 + NONCE_LENGTH + 4 + 8 + Raiha::TLS::Crypto::AEAD::TAG_LENGTH

    # The key a server seals its NEW_TOKEN tokens with.
    def self.key(retry_token_key)
      Raiha::TLS::KeySchedule.expand_label(secret: retry_token_key, label: "new token", length: 32, hash: :sha256, prefix: "raiha ")
    end

    def self.mint(key:, address:, version:, time:, random:)
      nonce = random.bytes(NONCE_LENGTH).b
      header = [KIND].pack("C")
      sealed = Raiha::TLS::Crypto::AEAD.new(:aes_256_gcm, key).seal(nonce:, aad: header + bound(address),
        plaintext: [version, time.to_i + LIFETIME].pack("NQ>"))
      header + nonce + sealed
    end

    # Whether `token` is one made for `address` and `version` that has not
    # expired.
    def self.valid?(token, key:, address:, version:, time:)
      return false unless token.bytesize == LENGTH && token.getbyte(0) == KIND
      header = token.byteslice(0, 1).to_s
      nonce = token.byteslice(1, NONCE_LENGTH).to_s
      opened = Raiha::TLS::Crypto::AEAD.new(:aes_256_gcm, key).open(nonce:, aad: header + bound(address),
        ciphertext: token.byteslice(1 + NONCE_LENGTH..).to_s) or return false
      sealed_version, expiry = opened.unpack("NQ>")
      sealed_version == version && time.to_i <= expiry.to_i
    end

    private_class_method def self.bound(address) = IPAddr.new(address.fetch(0)).hton
  end
end
