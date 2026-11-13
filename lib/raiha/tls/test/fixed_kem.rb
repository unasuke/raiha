# frozen_string_literal: true

module Raiha::Next::TLS::Test
  # A key exchange provider that uses one fixed private key per group, so
  # that tests can reproduce the key shares of RFC 8448. It reuses key
  # shares, which RFC 9846 forbids: never use it outside tests.
  class FixedKEM
    def initialize(private_keys)
      @private_keys = private_keys.dup.freeze
      @provider = Raiha::Next::TLS::KeyExchange::OpenSSL.new
    end

    def supported_groups = @private_keys.keys

    def generate(group)
      bytes = @private_keys.fetch(group) { raise ArgumentError, "no fixed key for #{group.inspect}" }
      key = Raiha::Next::TLS::Crypto::ECDH.private_key(group, bytes)
      public_bytes = Raiha::Next::TLS::Crypto::ECDH.public_bytes(group, key).freeze
      Raiha::Next::TLS::KeyExchange::KeyPair.new(group:, public_bytes:, private_key: key)
    end

    def encapsulate(group, peer_public_bytes)
      key_pair = generate(group)
      shared_secret = decapsulate(key_pair, peer_public_bytes) or return nil
      [key_pair.public_bytes, shared_secret]
    end

    def decapsulate(key_pair, ciphertext) = @provider.decapsulate(key_pair, ciphertext)
  end
end
