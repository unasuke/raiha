# frozen_string_literal: true

require_relative "../codec"
require_relative "message"
require_relative "violation"

module Raiha::TLS
  module Handshake
    # Empty. Sent over TCP only; QUIC forbids it.
    class EndOfEarlyData < Data.define
      include Message

      MSG_TYPE = 5

      def self.parse_body(body, registry: nil)
        Codec::Reader.new(body).finish!
        new
      end

      def msg_type = MSG_TYPE

      # Nothing to check without context.
      def validate = nil

      def write_body(w) = nil
    end
  end
end
