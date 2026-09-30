# frozen_string_literal: true

require_relative "../codec"
require_relative "../masked_inspect"
require_relative "message"
require_relative "violation"

module Raiha::Next::TLS
  module Handshake
    # verify_data has no length prefix: it is the whole body, and its length
    # must equal the negotiated hash's. Only the state machine knows the hash,
    # so the length is checked there.
    class Finished < Data.define(:verify_data)
      include Message
      include MaskedInspect

      MSG_TYPE = 20

      def self.parse_body(body, registry: nil)
        r = Codec::Reader.new(body)
        new(verify_data: r.bytes(r.remaining))
      end

      def msg_type = MSG_TYPE

      # Nothing to check without context.
      def validate = nil

      def write_body(w)
        w.bytes(verify_data)
      end

      def masked_members = %i[verify_data]
    end
  end
end
