# frozen_string_literal: true

require "securerandom"
require "stringio"

module Raiha::TLS
  class Handshake
    HANDSHAKE_TYPE = {
      client_hello: 1,
      server_hello: 2,
      new_session_ticket: 4,
      end_of_early_data: 5,
      encrypted_extensions: 8,
      certificate: 11,
      certificate_request: 13,
      certificate_verify: 15,
      finished: 20,
      key_update: 24,
      message_hash: 254
    }.freeze

    attr_accessor :handshake_type
    attr_accessor :length
    attr_accessor :message

    def serialize
      buf = String.new(encoding: "BINARY")
      buf << [handshake_type].pack("C*")
      serialized_message = message.serialize
      buf << [serialized_message.bytesize].pack("N").byteslice(1..) # uint24
      buf << serialized_message
      buf
    end

    def self.deserialize(data)
      hs = self.new
      buf = StringIO.new(data)
      type = buf.read(1).unpack1("C")
      raise "unknown handshake type: #{type}" unless HANDSHAKE_TYPE.value?(type)

      hs.handshake_type = type
      hs.length = ("\x00" + buf.read(3)).unpack1("N")
      hs.message = Message.deserialize(data: buf.read(hs.length), type: hs.handshake_type)
      hs
    end
  end

  class Message
    def serialize
      raise NotImplementedError
    end

    def self.deserialize(data:, type:)
      case type
      when Handshake::HANDSHAKE_TYPE[:client_hello]
        ClientHello.deserialize(data)
      else
        raise "unknown message type: #{type}"
      end
    end
  end

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

  class ServerHello < Message
    attr_accessor :random
    attr_accessor :legacy_session_id_echo
    attr_accessor :cipher_suite
    attr_accessor :extensions
  end

  class CipherSuite
    TLS_AES_128_GCM_SHA256 = [0x13, 0x01]
    TLS_AES_256_GCM_SHA384 = [0x13, 0x02]
    TLS_CHACHA20_POLY1305_SHA256 = [0x13, 0x03]
    TLS_AES_128_CCM_SHA256 = [0x13, 0x04]
    TLS_AES_128_CCM_8_SHA256 = [0x13, 0x05]

    def initialize(cipher_name)
      raise "unknown cipher suite: #{cipher_name.inspect}" unless self.class.constants.include?(cipher_name)

      @name = cipher_name
    end

    def value
      self.class.const_get(@name)
    end

    def serialize
      value.pack("C*")
    end

    def self.deserialize(data)
      val = data.unpack("CC")
      self.new(self.constants.find { |c| self.const_get(c) == val })
    end
  end

  class Extension
    EXTENSION_TYPE = {
      server_name: 0,
      max_fragment_length: 1,
      status_request: 5,
      supported_groups: 10,
      signature_algorithms: 13,
      use_srtp: 14,
      heartbeat: 15,
      application_layer_protocol_negotiation: 16,
      signed_certificate_timestamp: 18,
      client_certificate_type: 19,
      server_certificate_type: 20,
      padding: 21,
      pre_shred_key: 41,
      early_data: 42,
      supported_versions: 43,
      cookie: 44,
      psk_key_exchange_modes: 45,
      certificate_authorities: 47,
      oid_filters: 48,
      post_handshake_auth: 49,
      signature_algorithms_cert: 50,
      key_share: 51
    }.freeze

    attr_accessor :extension_type
    attr_accessor :extension_data

    def serialize
      packed_extension_data = extension_data.pack("C*")
      [extension_type].pack("n") + [packed_extension_data.bytesize].pack("n") + packed_extension_data
    end

    def self.deserialize_extensions(data)
      extensions = []
      buf = StringIO.new(data)
      until buf.eof?
        extension = self.new
        extension.extension_type = buf.read(2).unpack1("n")
        extension_data_length = buf.read(2).unpack1("n")
        extension.extension_data = buf.read(extension_data_length)
        extensions << extension
      end
      extensions
    end

    # def inspect
    #   readable_extension_type = EXTENSION_TYPE.invert[extension_type] || "unknown(#{extension_type})"
    #   "<#{self.class.name} @extension_type=#{readable_extension_type} @extension_data=#{extension_data.unpack1("H*").scan(/../).join(" ")}>"
    # end
  end
end
