require_relative "../extension"

module Raiha
  module TLS
    class Handshake
      class ClientHello < Message
        LEGACY_VERSION = [0x03, 0x03]
        TLS13_SUPPORTED_VERSION = [0x03, 0x04]

        attr_accessor :random
        attr_accessor :legacy_session_id
        attr_accessor :cipher_suites
        attr_accessor :legacy_compression_methods
        attr_accessor :extensions

        def self.build
          ch = self.new
          ch.random = SecureRandom.random_bytes(32)
          ch.legacy_session_id = 0x00
          ch.cipher_suites = [
            CipherSuite.new(:TLS_AES_128_GCM_SHA256),
            CipherSuite.new(:TLS_CHACHA20_POLY1305_SHA256),
            CipherSuite.new(:TLS_AES_256_GCM_SHA384),
          ]
          ch.legacy_compression_methods = [0x00]
          ch.extensions = ch.extensions_for_client_hello
          ch
        end

        def self.deserialize(data)
          ch = self.new
          buf = StringIO.new(data)
          buf.read(2) # legacy version
          ch.random = buf.read(32)
          ch.legacy_session_id = buf.read(1).unpack1("C") # 0xc00
          cipher_suites_count = buf.read(2).unpack1("n") / 2
          ch.cipher_suites = (1..cipher_suites_count).map { CipherSuite.deserialize(buf.read(2)) }
          ch.legacy_compression_methods = [0x00]; buf.read(2)
          extensions_bytesize = buf.read(2).unpack1("n")
          ch.extensions = Extension.deserialize_extensions(buf.read(extensions_bytesize))
          ch
        end

        # Build extensions for ClientHello
        def extensions_for_client_hello
          [
            Extension.new.tap do |ext|
              ext.extension_type = Extension::EXTENSION_TYPE[:supported_versions]
              ext.extension_data = TLS13_SUPPORTED_VERSION
            end,
            Extension.new.tap do |ext|
              ext.extension_type = Extension::EXTENSION_TYPE[:supported_groups]
              ext.extension_data = [0x03, 0x04]
            end,
            Extension.new.tap do |ext|
              ext.extension_type = Extension::EXTENSION_TYPE[:signature_algorithms]
              ext.extension_data = [0x03, 0x04]
            end
          ]
        end

        def serialize
          buf = String.new(encoding: "BINARY")
          buf << LEGACY_VERSION.pack("C*")
          buf << random
          buf << legacy_session_id
          buf << serialize_cipher_suites
          buf << "\x01" + legacy_compression_methods.pack("C*") # 0x01 is length
          buf << serialize_extensions
          buf
        end

        def serialize_cipher_suites
          buf = cipher_suites.map(&:serialize).join
          [buf.bytesize].pack("n") + buf
        end

        def serialize_extensions
          buf = extensions.map(&:serialize).join
          [buf.bytesize].pack("n") + buf
        end
      end
    end
  end
end
