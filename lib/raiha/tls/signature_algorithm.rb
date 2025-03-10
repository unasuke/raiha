# frozen_string_literal: true

module Raiha
  module TLS
    class SignatureAlgorithm
      # https://www.rfc-editor.org/rfc/rfc8446#appendix-B.3.1.3

      # RSASSA-PKCS1-v1_5 algorithms
      RSA_PKCS1_SHA256 = 0x0401
      RSA_PKCS1_SHA384 = 0x0501
      RSA_PKCS1_SHA512 = 0x0601

      # ECDSA algorithms
      ECDSA_SECP256R1_SHA256 = 0x0403
      ECDSA_SECP384R1_SHA384 = 0x0503
      ECDSA_SECP521R1_SHA512 = 0x0603

      # RSASSA-PSS algorithms with public key OID rsaEncryption
      RSA_PSS_RSAE_SHA256 = 0x0804
      RSA_PSS_RSAE_SHA384 = 0x0805
      RSA_PSS_RSAE_SHA512 = 0x0806

      # EdDSA algorithms
      ED25519 = 0x0807
      ED448 = 0x0808

      RSA_PKCS1_SHA256 = 0x0401
      RSA_PKCS1_SHA384 = 0x0501
      RSA_PKCS1_SHA512 = 0x0601
      RSA_PSS_PSS_SHA256 = 0x0809
      RSA_PSS_PSS_SHA384 = 0x080a
      RSA_PSS_PSS_SHA512 = 0x080b

      # Legacy algorithms
      RSA_PKCS1_SHA1 = 0x0201
      ECDSA_SHA1 = 0x0203

      # Reserved Code Points
      OBSOLETE_RESERVED = 0x0000..0x0200
      DSA_SHA1_RESERVED = 0x0202
      OBSOLETE_RESERVED = 0x0204..0x0400
      DSA_SHA256_RESERVED = 0x0402
      OBSOLETE_RESERVED = 0x0404..0x0500
      DSA_SHA384_RESERVED = 0x0502
      OBSOLETE_RESERVED = 0x0504..0x0600
      DSA_SHA512_RESERVED = 0x0602
      OBSOLETE_RESERVED = 0x0604..0x06ff
      PRIVATE_USE = 0xfe00..0xffff
    end
  end
end
