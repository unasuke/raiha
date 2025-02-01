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
        raise "unknown cipher suite: #{cipher_name.inspect}" unless CIPHER_SUITES.any? { |c| c[:name] == cipher_name }

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
          raise "TODO: hash algorithm for #{@name} is not supported" # TODO: really not supported?
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
          raise "TODO: aead algorithm for #{@name} is not supported" # TODO: really not supported?
        else
          raise "TODO: aead algorithm for #{@name} is not supported"
        end
      end

      def self.deserialize(data)
        self.new(CIPHER_SUITES.find { |c| c[:value] == data }[:name])
      end
    end
  end
end
