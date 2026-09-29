# frozen_string_literal: true

module Raiha::Next::TLS
  module Extension
    # An extension kept as its raw extension_data: one this implementation does
    # not know, or knows but does not interpret. Its contents are never
    # inspected, so trailing data inside it is not an error; RFC 9846 exempts
    # extensions the receiver does not implement from that check.
    class Opaque < Data.define(:type, :data)
      def extension_type = type

      def encode = data
    end
  end
end
