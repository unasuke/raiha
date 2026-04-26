# frozen_string_literal: true

module Raiha
  module TLS
    class SessionTicketStore
      def initialize
        @tickets = {}
      end

      def store(server_name, ticket_message, psk, application_data: nil)
        @tickets[server_name] = {
          ticket: ticket_message.ticket,
          ticket_nonce: ticket_message.ticket_nonce,
          psk: psk,
          received_at: Time.now,
          lifetime: ticket_message.ticket_lifetime,
          age_add: ticket_message.ticket_age_add,
          extensions: ticket_message.extensions,
          application_data: application_data,
        }
      end

      # Attach an opaque application-layer blob to an existing ticket entry
      # (RFC 9001 §4.6.1: QUIC servers/clients persist transport parameters
      # alongside the resumption ticket). Returns true when the entry exists.
      def attach_application_data(key, application_data)
        entry = @tickets[key]
        return false unless entry
        entry[:application_data] = application_data
        true
      end

      def get(server_name)
        entry = @tickets[server_name]
        return nil unless entry
        return nil if expired?(entry)

        entry
      end

      def get_by_ticket(ticket_data)
        @tickets.each_value do |entry|
          return entry if entry[:ticket] == ticket_data && !expired?(entry)
        end
        nil
      end

      def delete(server_name)
        @tickets.delete(server_name)
      end

      private def expired?(entry)
        Time.now > entry[:received_at] + entry[:lifetime]
      end
    end
  end
end
