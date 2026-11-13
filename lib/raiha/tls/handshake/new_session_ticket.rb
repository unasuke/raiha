# frozen_string_literal: true

require_relative "../codec"
require_relative "../extension"
require_relative "../masked_inspect"
require_relative "message"
require_relative "violation"

module Raiha::Next::TLS
  module Handshake
    # `ticket_lifetime` is not bounded here. The 7-day limit in RFC 9846 is a
    # rule for the sender and for how long a client may use the ticket, not a
    # reason to abort on receipt.
    class NewSessionTicket < Data.define(:ticket_lifetime, :ticket_age_add, :ticket_nonce, :ticket, :extensions)
      include Message
      include ExtensionLookup
      include MaskedInspect

      MSG_TYPE = 4

      def self.parse_body(body, registry:)
        r = Codec::Reader.new(body)
        ticket_lifetime = r.u32
        ticket_age_add = r.u32
        ticket_nonce = r.opaque(1, max: 0xff)
        ticket = r.opaque(2, min: 1, max: 0xffff)
        extensions = Extension.read_list(r, context: :new_session_ticket, registry:)
        r.finish!
        new(ticket_lifetime:, ticket_age_add:, ticket_nonce:, ticket:, extensions:)
      end

      def msg_type = MSG_TYPE

      # Nothing to check without context.
      def validate = nil

      def write_body(w)
        w.u32(ticket_lifetime)
        w.u32(ticket_age_add)
        w.vector(1, max: 0xff) { w.bytes(ticket_nonce) }
        w.vector(2, min: 1, max: 0xffff) { w.bytes(ticket) }
        Extension.write_list(w, extensions)
      end

      def masked_members = %i[ticket]
    end
  end
end
