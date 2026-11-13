# frozen_string_literal: true

require_relative "../codec"

module Raiha::Next::TLS
  module Extension
    # record_size_limit (RFC 8449 §4): `uint16 RecordSizeLimit`. A value
    # under MINIMUM is illegal_parameter.
    class RecordSizeLimit < Data.define(:record_size_limit)
      TYPE = 28
      MINIMUM = 64

      def self.parse(data)
        r = Codec::Reader.new(data)
        limit = r.u16
        r.finish!
        raise Codec::IllegalValue, "record_size_limit #{limit} is under #{MINIMUM}" if limit < MINIMUM
        new(record_size_limit: limit)
      end

      def extension_type = TYPE

      def encode
        w = Codec::Writer.new
        w.u16(record_size_limit)
        w.to_s
      end
    end
  end
end
