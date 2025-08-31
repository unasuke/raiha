require_relative "../extension"

module Raiha
  module TLS
    class Handshake
      # ClientHello
      #
      #   uint16 ProtocolVersion;
      #   opaque Random[32];
      #
      #   uint8 CipherSuite[2];    /* Cryptographic suite selector */
      #
      #   struct {
      #       ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
      #       Random random;
      #       opaque legacy_session_id<0..32>;
      #       CipherSuite cipher_suites<2..2^16-2>;
      #       opaque legacy_compression_methods<1..2^8-1>;
      #       Extension extensions<8..2^16-1>;
      #   } ClientHello;
      # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
      class ClientHello < Message
        LEGACY_VERSION = "\x03\x03"
        TLS13_SUPPORTED_VERSION = [0x03, 0x04]

        attr_accessor :random
        attr_accessor :legacy_version
        attr_accessor :legacy_session_id
        attr_accessor :cipher_suites
        attr_accessor :legacy_compression_methods
        attr_accessor :extensions

        def self.build
          ch = self.new
          ch.legacy_version = LEGACY_VERSION
          ch.random = SecureRandom.random_bytes(32)
          ch.legacy_session_id = ""
          ch.cipher_suites = [
            CipherSuite.new(:TLS_AES_128_GCM_SHA256),
            # CipherSuite.new(:TLS_CHACHA20_POLY1305_SHA256), # TODO:
            # CipherSuite.new(:TLS_AES_256_GCM_SHA384),
          ]
          ch.legacy_compression_methods = 0
          ch.extensions = ch.extensions_for_client_hello
          ch
        end

        def self.deserialize(data)
          ch = self.new
          buf = StringIO.new(data)
          ch.legacy_version = buf.read(2)
          ch.random = buf.read(32)
          legacy_session_id_length = buf.read(1).unpack1("C") # 0xc00
          ch.legacy_session_id = buf.read(legacy_session_id_length)
          cipher_suites_count = buf.read(2).unpack1("n") / 2
          ch.cipher_suites = (1..cipher_suites_count).map { CipherSuite.deserialize(buf.read(2)) }
          legacy_compression_methods_length = buf.read(1).unpack1("C")
          ch.legacy_compression_methods = buf.read(legacy_compression_methods_length).unpack1("C*")
          extensions_bytesize = buf.read(2).unpack1("n")
          ch.extensions = Extension.deserialize_extensions(buf.read(extensions_bytesize), type: :client_hello)
          ch
        end

        # Build extensions for ClientHello
        def extensions_for_client_hello
          [
            Extension::SupportedVersions.generate_for_tls13,
            Extension::SupportedGroups.new(on: :client_hello).tap do |ext|
              ext.groups = ["prime256v1"]
            end,
            Extension::SignatureAlgorithms.new(on: :client_hello).tap do |ext|
              # ext.signature_schemes = ["rsa_pss_rsae_sha256"]
              ext.signature_schemes = ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"]
            end,
          ]
        end

        def serialize
          buf = String.new(encoding: "BINARY")
          buf << LEGACY_VERSION
          buf << random
          buf << [legacy_session_id.bytesize].pack("C")
          buf << legacy_session_id
          buf << serialize_cipher_suites
          buf << "\x01" + [legacy_compression_methods].pack("C") # 0x01 is length
          buf << serialize_extensions
          buf
        end

        def setup_key_share(group_and_pkeys)
          @extensions << Extension::KeyShare.setup(group_and_pkeys)
        end

        def serialize_cipher_suites
          # TODO: move to abstract class?
          buf = cipher_suites.map(&:serialize).join
          [buf.bytesize].pack("n") + buf
        end

        def serialize_extensions
          # TODO: move to abstract class?
          buf = extensions.map(&:serialize).join
          [buf.bytesize].pack("n") + buf
        end

        def key_share
          @extensions.find { |ext| ext.is_a?(Extension::KeyShare) }
        end

        def valid_legacy_version?
          legacy_version == LEGACY_VERSION
        end

        def server_name=(server_name)
          ext = @extensions.find { |e| e.is_a?(Extension::ServerName) }
          if ext
            ext.server_name = server_name
          else
            ext = Extension::ServerName.new(on: :client_hello)
            ext.server_name = server_name
            @extensions << ext
          end
        end
      end
    end
  end
end
