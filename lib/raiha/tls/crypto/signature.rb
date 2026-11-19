# frozen_string_literal: true

module Raiha::TLS
  module Crypto
    # Signing and verifying for a SignatureScheme, and the keys they use.
    #
    # RSA keys sign only with RSASSA-PSS here (rsa_pss_rsae_*); an RSASSA-PSS
    # key (rsa_pss_pss_*) is not supported. RSASSA-PKCS1-v1_5 appears only in
    # certificate signatures, which X509::Store verifies.
    module Signature
      # The digests a SignatureScheme may name, wider than the cipher suites'.
      DIGESTS = { sha256: "SHA256", sha384: "SHA384", sha512: "SHA512" }.freeze #: Hash[Symbol, String]

      CURVES = { "prime256v1" => :secp256r1, "secp384r1" => :secp384r1, "secp521r1" => :secp521r1 }.freeze #: Hash[String, Symbol]

      # A private key from DER (PKCS #8 or the traditional forms), or nil.
      # An Ed25519 key comes as a plain OpenSSL::PKey::PKey, which does not
      # tell whether it is private; one is when its raw private key reads.
      def self.private_key(der)
        key = OpenSSL::PKey.read(der)
        private = key.respond_to?(:private?) ? key.private? : !key.raw_private_key.nil? # steep:ignore
        private ? key : nil
      rescue OpenSSL::PKey::PKeyError, ArgumentError
        nil
      end

      # Whether `key` is of the kind `scheme` signs with: an RSA key for
      # RSASSA-PSS with rsaEncryption, and a key on the scheme's curve for
      # ECDSA and EdDSA. An EdDSA key is told by its name in lower case,
      # since OpenSSL says "ED25519" where LibreSSL says "Ed25519".
      def self.key_matches?(scheme, key)
        case scheme.family
        when :rsa_pss_rsae, :rsa_pkcs1
          key.oid == "rsaEncryption"
        when :ecdsa
          case key
          when OpenSSL::PKey::EC then CURVES[key.group.curve_name] == scheme.curve
          else false
          end
        when :eddsa
          key.oid.downcase == scheme.curve.to_s
        else
          false
        end
      end

      def self.sign(scheme, key, data)
        case scheme.family
        when :rsa_pss_rsae
          digest = digest_name(scheme)
          key.sign_pss(digest, data, salt_length: :digest, mgf1_hash: digest)
        when :ecdsa
          key.sign(digest_name(scheme), data)
        when :eddsa
          key.sign(nil, data)
        else
          raise ArgumentError, "#{scheme.name} cannot sign a CertificateVerify"
        end
      end

      # False rather than an exception for a signature from the peer that
      # does not verify, however malformed. RFC 9846 requires an RSASSA-PSS
      # salt as long as the digest.
      def self.verify(scheme, key, signature, data)
        return false unless key_matches?(scheme, key)
        case scheme.family
        when :rsa_pss_rsae
          digest = digest_name(scheme)
          key.verify_pss(digest, signature, data, salt_length: :digest, mgf1_hash: digest)
        when :ecdsa
          key.verify(digest_name(scheme), signature, data)
        when :eddsa
          key.verify(nil, signature, data)
        else
          false
        end
      rescue OpenSSL::PKey::PKeyError
        false
      end

      private_class_method def self.digest_name(scheme)
        algorithm = scheme.hash_algorithm or raise ArgumentError, "#{scheme.name} signs without a separate digest"
        DIGESTS.fetch(algorithm) { raise ArgumentError, "#{scheme.name} has no usable digest" }
      end
    end
  end
end
