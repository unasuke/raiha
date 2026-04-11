# frozen_string_literal: true

module Raiha
  module TLS
    class SessionTicketStore
      def initialize
        @tickets = {}
      end

      def store(server_name, ticket_message, psk)
        @tickets[server_name] = {
          ticket: ticket_message.ticket,
          ticket_nonce: ticket_message.ticket_nonce,
          psk: psk,
          received_at: Time.now,
          lifetime: ticket_message.ticket_lifetime,
          age_add: ticket_message.ticket_age_add,
          extensions: ticket_message.extensions,
        }
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
