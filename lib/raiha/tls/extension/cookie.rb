# frozen_string_literal: true

require_relative "../codec"

module Raiha::TLS
  module Extension
    # cookie: `opaque cookie<1..2^16-1>`.
    class Cookie < Data.define(:cookie)
      TYPE = 44

      def self.parse(data)
        r = Codec::Reader.new(data)
        cookie = r.opaque(2, min: 1, max: 0xffff)
        r.finish!
        new(cookie:)
      end

      def extension_type = TYPE

      def encode
        w = Codec::Writer.new
        w.vector(2, min: 1, max: 0xffff) { w.bytes(cookie) }
        w.to_s
      end
    end
  end
end
