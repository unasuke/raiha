module Raiha
  module TLS
    class ChangeCipherSpec
      attr_accessor :content

      def self.deserialize(buf)
        self.new.tap do |change_cipher_spec|
          change_cipher_spec.content = buf
        end
      end
    end
  end
end
