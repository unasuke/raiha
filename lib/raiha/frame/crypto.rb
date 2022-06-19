require 'raiha/frame/base'
require 'raiha/tls'

module Raiha
  module Frame
    class Crypto < Base
      def parse
        byte :type, size: 1 # 0x06
        var_len_int :offset
        var_len_int :length
        byte :crypto_data, size: :length

        self
      end

      def tls_message
        ::Raiha::Tls.new.parse([@parsed[:crypto_data][:value]].pack("B*"))
      end
    end
  end
end
