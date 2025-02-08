require_relative "abstract_extension"
require "stringio"

module Raiha
  module TLS
    class Handshake
      class Extension
        # SignatureAlgorithms
        #
        #   enum {
        #       /* RSASSA-PKCS1-v1_5 algorithms */
        #       rsa_pkcs1_sha256(0x0401),
        #       rsa_pkcs1_sha384(0x0501),
        #       rsa_pkcs1_sha512(0x0601),
        #
        #       /* ECDSA algorithms */
        #       ecdsa_secp256r1_sha256(0x0403),
        #       ecdsa_secp384r1_sha384(0x0503),
        #       ecdsa_secp521r1_sha512(0x0603),
        #
        #       /* RSASSA-PSS algorithms with public key OID rsaEncryption */
        #       rsa_pss_rsae_sha256(0x0804),
        #       rsa_pss_rsae_sha384(0x0805),
        #       rsa_pss_rsae_sha512(0x0806),
        #
        #       /* EdDSA algorithms */
        #       ed25519(0x0807),
        #       ed448(0x0808),
        #
        #       /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
        #       rsa_pss_pss_sha256(0x0809),
        #       rsa_pss_pss_sha384(0x080a),
        #       rsa_pss_pss_sha512(0x080b),
        #
        #       /* Legacy algorithms */
        #       rsa_pkcs1_sha1(0x0201),
        #       ecdsa_sha1(0x0203),
        #
        #       /* Reserved Code Points */
        #       private_use(0xFE00..0xFFFF),
        #       (0xFFFF)
        #   } SignatureScheme;
        #
        #   struct {
        #       SignatureScheme supported_signature_algorithms<2..2^16-2>;
        #   } SignatureSchemeList;
        #
        # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
        # @see https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.3
        # @see https://datatracker.ietf.org/doc/rfc8446/
        class SignatureAlgorithms < AbstractExtension
          EXTENSION_TYPE_NUMBER = 13

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

          PRIVATE_USE = (0xFE00..0xFFFF)
          OBSOLETE_RESERVEDS = [
            (0x0000..0x0200), (0x0204..0x0400), (0x0404..0x0500), (0x0504..0x0600), (0x0604..0x06FF)
          ].freeze

          attr_accessor :signature_schemes

          def extension_data=(data)
            super

            @signature_schemes = []
            buf = StringIO.new(data)
            signature_schemes_length = buf.read(2).unpack1("n") / 2
            signature_schemes_length.times do
              signature_scheme_id = buf.read(2)
              signature_scheme = SIGNATURE_SCHEMES.key(signature_scheme_id)
              if signature_scheme
                @signature_schemes << signature_scheme
              elsif PRIVATE_USE.include?(signature_scheme_id)
                @signature_schemes << "private_use"
              elsif OBSOLETE_RESERVEDS.any? { |obsolete| obsolete.include?(signature_scheme_id) }
                @signature_schemes << "obsolete_reserved"
              else
                # TODO: raise error?
              end
            end
          end

          def serialize
            data = [@signature_schemes.length * 2].pack("n") +
                   @signature_schemes.map { |scheme| SIGNATURE_SCHEMES[scheme] }.join
            [EXTENSION_TYPE_NUMBER].pack("n") + [data.bytesize].pack("n") + data
          end
        end
      end
    end
  end
end
