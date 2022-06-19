module Raiha
  module Frame
    class Base
      attr_reader :raw
      attr_reader :parsed
      attr_reader :protected

      def initialize(data)
        @raw = data
        @packed = @raw.unpack1("B*")
        @parsed = {}
        @cursor = 0
      end

      def parse
        raise NotImplementedError
      end

      def bit(name, size:, type: :raw)
        if size.is_a?(Symbol)
          bits = @packed[@cursor...(@cursor+@parsed[size][:value])]
          @cursor += @parsed[size][:value]
        else
          bits = @packed[@cursor...(@cursor+size)]
          @cursor += size
        end

        @parsed[name.to_sym] = case type
        when :raw then {raw: bits, value: bits}
        when :int then {raw: bits, value: bits.to_i(2)}
        else raise NotImplementedError
        end
      end

      def byte(name, size:, type: :raw)
        if size.is_a?(Symbol)
          bits = @packed[@cursor...(@cursor+ @parsed[size][:value]*8)]
          @cursor += @parsed[size][:value] * 8
        else
          bits = @packed[@cursor...(@cursor + size*8)]
          @cursor += size * 8
        end

        @parsed[name.to_sym] = case type
        when :raw then {raw: bits, value: bits}
        when :int then {raw: bits, value: bits.to_i(2)}
        else raise NotImplementedError
        end
      end

      # Variable Length Integer Encoding
      # https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc
      def var_len_int(name)
        raw = ""
        two_msb = @packed[@cursor..@cursor+1]
        raw += two_msb
        @cursor += 2
        length = 2 ** two_msb.to_i(2) * 8 - 2
        @parsed[name.to_sym] = {
          raw: raw += @packed[@cursor...@cursor+length],
          value: @packed[@cursor...@cursor+length].to_i(2)
        }
        @cursor += length
      end

      def var_len_int_byte_length(two_most_significant_bits)
        case two_most_significant_bits
        when "00"
          1
        when "01"
          2
        when "10"
          4
        when "11"
          8
        end
      end
    end
  end
end
