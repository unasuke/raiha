# frozen_string_literal: true

require_relative "../codec"

module Raiha::Next::TLS
  module Extension
    # psk_key_exchange_modes: `PskKeyExchangeMode ke_modes<1..255>`.
    class PskKeyExchangeModes < Data.define(:ke_modes)
      TYPE = 45

      def self.parse(data)
        r = Codec::Reader.new(data)
        modes = r.vector(1, min: 1, max: 0xff) do |v|
          # @type var list: Array[Integer]
          list = []
          list << v.u8 until v.eof?
          list.freeze
        end
        r.finish!
        new(ke_modes: modes)
      end

      def extension_type = TYPE

      def encode
        w = Codec::Writer.new
        w.vector(1, min: 1, max: 0xff) { ke_modes.each { |mode| w.u8(mode) } }
        w.to_s
      end
    end
  end
end
