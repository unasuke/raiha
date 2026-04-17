require_relative "error"

module Raiha
  module TLS
    class CipherSuite
      CIPHER_SUITES = [
        { name: :TLS_AES_128_GCM_SHA256, value: "\x13\x01", supported: true },
        { name: :TLS_AES_256_GCM_SHA384, value: "\x13\x02", supported: true },
        { name: :TLS_CHACHA20_POLY1305_SHA256, value: "\x13\x03", supported: true },
        { name: :TLS_AES_128_CCM_SHA256, value: "\x13\x04", supported: false },
        { name: :TLS_AES_128_CCM_8_SHA256, value: "\x13\x05", supported: false },
      ]

      attr_reader :name
      attr_reader :value

      def initialize(cipher_name)
        raise Raiha::TLS::Error, "unknown cipher suite: #{cipher_name.inspect}" unless CIPHER_SUITES.any? { |c| c[:name] == cipher_name }

        cipher_suite = CIPHER_SUITES.find { |c| c[:name] == cipher_name }
        @name = cipher_suite[:name]
        @value = cipher_suite[:value]
        @supported = cipher_suite[:supported]
      end

      def serialize
        @value
      end

      def supported?
        @supported
      end

      def hash_algorithm
        @hash_algorithm ||= case @name
        when :TLS_AES_128_GCM_SHA256, :TLS_CHACHA20_POLY1305_SHA256, :TLS_AES_128_CCM_SHA256
          "SHA256"
        when :TLS_AES_256_GCM_SHA384
          "SHA384"
        else
          raise Raiha::TLS::Error, "TODO: hash algorithm for #{@name} is not supported" # TODO: really not supported?
        end
      end

      def aead_algorithm
        @aead_algorithm ||= case @name
        when :TLS_AES_128_GCM_SHA256
          "aes-128-gcm"
        when :TLS_AES_256_GCM_SHA384
          "aes-256-gcm"
        when :TLS_CHACHA20_POLY1305_SHA256
          "chacha20-poly1305"
        when :TLS_AES_128_CCM_SHA256
          "aes-128-ccm"
        when :TLS_AES_128_CCM_8_SHA256
          raise Raiha::TLS::Error, "TODO: aead algorithm for #{@name} is not supported" # TODO: really not supported?
        else
          raise Raiha::TLS::Error, "TODO: aead algorithm for #{@name} is not supported"
        end
      end

      def self.deserialize(data)
        entry = CIPHER_SUITES.find { |c| c[:value] == data }
        if entry
          self.new(entry[:name])
        else
          # Preserve unknown cipher suites for roundtrip fidelity
          cs = allocate
          cs.instance_variable_set(:@name, :"unknown_#{data.unpack1("H4")}")
          cs.instance_variable_set(:@value, data)
          cs.instance_variable_set(:@supported, false)
          cs
        end
      end
    end
  end
end
