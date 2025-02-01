require "securerandom"
require_relative "../extension"

module Raiha
  module TLS
    class Handshake
      # ServerHello
      #
      #   struct {
      #      ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
      #      Random random;
      #      opaque legacy_session_id_echo<0..32>;
      #      CipherSuite cipher_suite;
      #      uint8 legacy_compression_method = 0;
      #      Extension extensions<6..2^16-1>;
      #   } ServerHello;
      # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
      class ServerHello < Message
        # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
        HELLO_RETRY_REQUEST_RANDOM = [<<~RANDOM.gsub(/[[:space:]]/, '')].pack("H*")
          cf 21 ad 74 e5 9a 61 11 be 1d 8c 02 1e 65 b8 91
          c2 a2 11 16 7a bb 8c 5e 07 9e 09 e2 c8 a8 33 9c
        RANDOM

        # TODO: move to super class (using same value in ClientHello also)
        LEGACY_VERSION = [0x03, 0x03]

        # TODO: move to super class (using same value in ClientHello also)
        TLS13_SUPPORTED_VERSION = [0x03, 0x04]

        attr_accessor :random
        attr_accessor :legacy_session_id_echo
        attr_accessor :legacy_compression_method
        attr_accessor :cipher_suite
        attr_accessor :extensions

        def self.build_from_client_hello(client_hello)
          # TODO:
          sh = self.new
          loop do
            sh.random = SecureRandom.random_bytes(32)
            break if sh.random != HELLO_RETRY_REQUEST_RANDOM
          end
          sh.legacy_session_id_echo = client_hello.legacy_session_id
          sh.cipher_suite = client_hello.cipher_suites.find(&:supported?)
          sh
        end

        # Sets default values to cipher_suite and extensions (empty values)
        def initialize
          super
          @cipher_suite = nil
          @extensions = [
            # Mandatory extension
            # https://www.ietf.org/archive/id/draft-ietf-tls-rfc8446bis-11.html#section-4.1.3-4.12.1
            Extension::SupportedVersions.generate_for_tls13
          ]
          @legacy_compression_method = 0
        end

        def serialize
          buf = String.new(encoding: "BINARY")
          buf << LEGACY_VERSION.pack("C*")
          buf << random
          buf << [legacy_session_id_echo].pack("C")
          buf << cipher_suite.serialize
          buf << [0].pack("C") # legacy compression method
          buf << serialize_extensions
          buf
        end

        def self.deserialize(data)
          sh = self.new
          buf = StringIO.new(data)
          buf.read(2) # legacy version
          sh.random = buf.read(32)
          sh.legacy_session_id_echo = buf.read(1).unpack1("C") # 0x00
          sh.cipher_suite = CipherSuite.deserialize(buf.read(2))
          sh.legacy_compression_method = buf.read(1)
          extensions_bytesize = buf.read(2).unpack1("n")
          sh.extensions = Extension.deserialize_extensions(buf.read(extensions_bytesize), type: :server_hello)
          sh
        end

        def hello_retry_request?
          random == HELLO_RETRY_REQUEST_RANDOM
        end

        def serialize_extensions
          # TODO: move to abstract class?
          buf = extensions.map(&:serialize).join
          [buf.bytesize].pack("n") + buf
        end
      end
    end
  end
end
