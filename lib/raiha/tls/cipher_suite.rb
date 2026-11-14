# frozen_string_literal: true

require_relative "crypto"

module Raiha::TLS
  # A TLS 1.3 cipher suite: the AEAD and hash it names, and how much one key
  # may be used before it has to be updated.
  #
  # The usage limits differ by transport. Over TCP they come from RFC 9846
  # ("Limits on Key Usage"), which counts full-size records and sets no
  # integrity limit because a TLS connection ends at the first forgery. Over
  # QUIC they come from RFC 9001 ("Limits on AEAD Usage"), which counts
  # packets and also limits failed decryptions. nil means no limit.
  #
  # The hash is `hash_algorithm`, not `hash`, so that `Object#hash` still
  # works and a suite can be a Hash key.
  class CipherSuite < Data.define(:id, :name, :hash_algorithm, :aead, :key_length, :iv_length, :tag_length, :limits)
    Limits = Data.define(:confidentiality, :integrity)

    def hash_length = Crypto.hash_length(hash_algorithm)

    def confidentiality_limit(transport) = limits.fetch(transport).confidentiality

    def integrity_limit(transport) = limits.fetch(transport).integrity

    # 2^24.5 records, rounded down.
    AES_GCM_TCP_CONFIDENTIALITY_LIMIT = 23_726_566

    AES_GCM_LIMITS = {
      tcp: Limits.new(confidentiality: AES_GCM_TCP_CONFIDENTIALITY_LIMIT, integrity: nil),
      quic: Limits.new(confidentiality: 1 << 23, integrity: 1 << 52)
    }.freeze

    TLS_AES_128_GCM_SHA256 = new(
      id: 0x1301, name: :TLS_AES_128_GCM_SHA256, hash_algorithm: :sha256, aead: :aes_128_gcm,
      key_length: 16, iv_length: 12, tag_length: 16, limits: AES_GCM_LIMITS
    )

    TLS_AES_256_GCM_SHA384 = new(
      id: 0x1302, name: :TLS_AES_256_GCM_SHA384, hash_algorithm: :sha384, aead: :aes_256_gcm,
      key_length: 32, iv_length: 12, tag_length: 16, limits: AES_GCM_LIMITS
    )

    # The record sequence number wraps before any confidentiality limit, and
    # RFC 9001 puts it beyond the 2^62 packets QUIC can send.
    CHACHA20_POLY1305_LIMITS = {
      tcp: Limits.new(confidentiality: nil, integrity: nil),
      quic: Limits.new(confidentiality: nil, integrity: 1 << 36)
    }.freeze

    TLS_CHACHA20_POLY1305_SHA256 = new(
      id: 0x1303, name: :TLS_CHACHA20_POLY1305_SHA256, hash_algorithm: :sha256, aead: :chacha20_poly1305,
      key_length: 32, iv_length: 12, tag_length: 16, limits: CHACHA20_POLY1305_LIMITS
    )

    # The suites this implementation can negotiate. The two CCM suites of RFC
    # 9846 are left out; when offered they are ignored like any unknown suite.
    SUITES = [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256].to_h { |suite| [suite.id, suite] }.freeze

    def self.find(id) = SUITES[id]
  end
end
