module Raiha
  module TLS
    class CipherSuite
      TLS_AES_128_GCM_SHA256 = [0x13, 0x01]
      TLS_AES_256_GCM_SHA384 = [0x13, 0x02]
      TLS_CHACHA20_POLY1305_SHA256 = [0x13, 0x03]
      TLS_AES_128_CCM_SHA256 = [0x13, 0x04]
      TLS_AES_128_CCM_8_SHA256 = [0x13, 0x05]

      SUPPORTED_CIPHER_SUITES = [:TLS_AES_128_GCM_SHA256, :TLS_AES_256_GCM_SHA384, :TLS_CHACHA20_POLY1305_SHA256]

      attr_reader :name

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

      def supported?
        SUPPORTED_CIPHER_SUITES.include?(@name.to_sym)
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
        val = data.unpack("CC")
        self.new(self.constants.find { |c| self.const_get(c) == val })
      end
    end
  end
end
