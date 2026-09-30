# frozen_string_literal: true

module Raiha::Next::TLS
  # A SignatureScheme of RFC 9846: the signature algorithm, the hash it uses
  # and, for ECDSA and EdDSA, the curve the key must be on.
  #
  # RSASSA-PKCS1-v1_5 and SHA-1 may sign certificates but never a
  # CertificateVerify, which `#usable_in_certificate_verify?` says.
  class SignatureScheme < Data.define(:id, :name, :family, :hash_algorithm, :curve)
    def usable_in_certificate_verify? = family != :rsa_pkcs1 && hash_algorithm != :sha1

    SCHEMES = [
      new(id: 0x0401, name: :rsa_pkcs1_sha256, family: :rsa_pkcs1, hash_algorithm: :sha256, curve: nil),
      new(id: 0x0501, name: :rsa_pkcs1_sha384, family: :rsa_pkcs1, hash_algorithm: :sha384, curve: nil),
      new(id: 0x0601, name: :rsa_pkcs1_sha512, family: :rsa_pkcs1, hash_algorithm: :sha512, curve: nil),
      new(id: 0x0403, name: :ecdsa_secp256r1_sha256, family: :ecdsa, hash_algorithm: :sha256, curve: :secp256r1),
      new(id: 0x0503, name: :ecdsa_secp384r1_sha384, family: :ecdsa, hash_algorithm: :sha384, curve: :secp384r1),
      new(id: 0x0603, name: :ecdsa_secp521r1_sha512, family: :ecdsa, hash_algorithm: :sha512, curve: :secp521r1),
      new(id: 0x0804, name: :rsa_pss_rsae_sha256, family: :rsa_pss_rsae, hash_algorithm: :sha256, curve: nil),
      new(id: 0x0805, name: :rsa_pss_rsae_sha384, family: :rsa_pss_rsae, hash_algorithm: :sha384, curve: nil),
      new(id: 0x0806, name: :rsa_pss_rsae_sha512, family: :rsa_pss_rsae, hash_algorithm: :sha512, curve: nil),
      new(id: 0x0807, name: :ed25519, family: :eddsa, hash_algorithm: nil, curve: :ed25519),
      new(id: 0x0808, name: :ed448, family: :eddsa, hash_algorithm: nil, curve: :ed448),
      new(id: 0x0809, name: :rsa_pss_pss_sha256, family: :rsa_pss_pss, hash_algorithm: :sha256, curve: nil),
      new(id: 0x080a, name: :rsa_pss_pss_sha384, family: :rsa_pss_pss, hash_algorithm: :sha384, curve: nil),
      new(id: 0x080b, name: :rsa_pss_pss_sha512, family: :rsa_pss_pss, hash_algorithm: :sha512, curve: nil),
      # Legacy: for certificate signatures only.
      new(id: 0x0201, name: :rsa_pkcs1_sha1, family: :rsa_pkcs1, hash_algorithm: :sha1, curve: nil),
      new(id: 0x0203, name: :ecdsa_sha1, family: :ecdsa, hash_algorithm: :sha1, curve: nil)
    ].to_h { |scheme| [scheme.id, scheme] }.freeze

    # nil for a code point this table does not define, GREASE included.
    def self.find(id) = SCHEMES[id]
  end
end
