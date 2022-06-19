module Raiha
  class Tls
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
    end
  end
end
