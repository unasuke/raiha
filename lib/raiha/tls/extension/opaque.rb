# frozen_string_literal: true

module Raiha::TLS
  module Extension
    # An extension kept as its raw extension_data: one this implementation does
    # not know, or knows but does not interpret. Its contents are never
    # inspected, so trailing data inside it is not an error; RFC 9846 exempts
    # extensions the receiver does not implement from that check.
    class Opaque < Data.define(:type, :data)
      # Parses the extension_data of one known type into an Opaque, so a
      # PLACEMENT row can list an extension without interpreting it.
      class Parser < Data.define(:type)
        def parse(data) = Opaque.new(type:, data:)
      end

      def extension_type = type

      def encode = data
    end
  end
end
