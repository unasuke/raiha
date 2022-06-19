require 'raiha/frame/base'

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
    end
  end
end
