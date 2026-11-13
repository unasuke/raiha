# frozen_string_literal: true

require_relative "../codec"

module Raiha::Next::TLS
  module Extension
    # application_layer_protocol_negotiation (RFC 7301 §3.1):
    # `ProtocolName protocol_name_list<2..2^16-1>` of `opaque ProtocolName<1..2^8-1>`.
    class Alpn < Data.define(:protocol_name_list)
      TYPE = 16

      def self.parse(data)
        r = Codec::Reader.new(data)
        names = r.vector(2, min: 2, max: 0xffff) do |v|
          # @type var list: Array[String]
          list = []
          list << v.opaque(1, min: 1, max: 0xff) until v.eof?
          list.freeze
        end
        r.finish!
        new(protocol_name_list: names)
      end

      def extension_type = TYPE

      def encode
        w = Codec::Writer.new
        w.vector(2, min: 2, max: 0xffff) do
          protocol_name_list.each { |name| w.vector(1, min: 1, max: 0xff) { w.bytes(name) } }
        end
        w.to_s
      end
    end
  end
end
