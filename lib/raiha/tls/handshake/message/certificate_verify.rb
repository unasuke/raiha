require "stringio"
require "openssl"

module Raiha
  module TLS
    class Handshake
      # CertificateVerify message
      #
      #    struct {
      #        SignatureScheme algorithm;
      #        opaque signature<0..2^16-1>;
      #    } CertificateVerify;
      #
      # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3
      class CertificateVerify < Message
        # TODO: move to somewhere
        SIGNATURE_SCHEMES = {
          # RSASSA-PKCS1-v1_5 algorithms
          "rsa_pkcs1_sha256" => "\x04\x01",
          "rsa_pkcs1_sha384" => "\x05\x01",
          "rsa_pkcs1_sha512" => "\x06\x01",

          # ECDSA algorithms
          "ecdsa_secp256r1_sha256" => "\x04\x03",
          "ecdsa_secp384r1_sha384" => "\x05\x03",
          "ecdsa_secp521r1_sha512" => "\x06\x03",

          # RSASSA-PSS algorithms with public key OID rsaEncryption
          "rsa_pss_rsae_sha256" => "\x08\x04",
          "rsa_pss_rsae_sha384" => "\x08\x05",
          "rsa_pss_rsae_sha512" => "\x08\x06",

          # EdDSA algorithms
          "ed25519" => "\x08\x07",
          "ed448" => "\x08\x08",

          # RSASSA-PSS algorithms with public key OID RSASSA-PSS
          "rsa_pss_pss_sha256" => "\x08\x09",
          "rsa_pss_pss_sha384" => "\x08\x0a",
          "rsa_pss_pss_sha512" => "\x08\x0b",

          # Legacy algorithms
          "rsa_pkcs1_sha1" => "\x02\x01",
          "ecdsa_sha1" => "\x02\x03",

          # Reserved Code Points (not obsolete)
          "dsa_sha1_RESERVED" => "\x02\x02",
          "dsa_sha256_RESERVED" => "\x04\x02",
          "dsa_sha384_RESERVED" => "\x05\x02",
          "dsa_sha512_RESERVED" => "\x06\x02",
        }.freeze

        attr_accessor :algorithm
        attr_accessor :signature

        def self.deserialize(data)
          cert_verify = self.new
          buf = StringIO.new(data)
          signature_scheme_id = buf.read(2)
          cert_verify.algorithm = SIGNATURE_SCHEMES.key(signature_scheme_id) # TODO: nil check

          signature_length = buf.read(2).unpack1("n")
          cert_verify.signature = buf.read(signature_length)
          raise unless buf.eof?

          cert_verify
        end

        def serialize
          buf = String.new(encoding: "BINARY")
          buf << SIGNATURE_SCHEMES[algorithm]
          buf << [signature.bytesize].pack("n")
          buf << signature
        end

        def sign(private_key, messages, context)
          @signature = private_key.sign_pss("sha256", signed_data(messages, context), salt_length: :digest, mgf1_hash: "sha256")
        end

        def verify_signature(certificate_message, messages, context)
          case algorithm
          when "rsa_pss_rsae_sha256"
            certificate_message.certificate.public_key.verify_pss("sha256", signature, signed_data(messages, context), salt_length: :auto, mgf1_hash: "sha256")
          else
            raise "TODO: #{algorithm} is not supported (yet)"
          end
        end

        private def signed_data(messages, context)
          ("\x20" * 64) + context + "\x00" + transcript_hash(messages)
        end

        private def transcript_hash(messages)
          # TODO: sha256 is hardcoded, move to somewhere
          hash = OpenSSL::Digest.new("sha256").new
          hash.update(messages.join)
          hash.digest
        end
      end
    end
  end
end
