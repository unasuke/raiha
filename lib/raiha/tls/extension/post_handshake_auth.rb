# frozen_string_literal: true

require_relative "../codec"

module Raiha::TLS
  module Extension
    # post_handshake_auth: empty. Parsed and encoded only; this implementation
    # never sends it, since it does not do post-handshake authentication.
    class PostHandshakeAuth < Data.define
      TYPE = 49

      def self.parse(data)
        Codec::Reader.new(data).finish!
        new
      end

      def extension_type = TYPE

      def encode = "".b
    end
  end
end
