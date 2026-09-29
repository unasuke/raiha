# frozen_string_literal: true

require_relative "../codec"
require_relative "message"

module Raiha::Next::TLS
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

      def write_body(w) = nil
    end
  end
end
