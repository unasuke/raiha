module Raiha
  module TLS
    class Handshake
      # NewSessionTicket message
      #
      #   struct {
      #       uint32 ticket_lifetime;
      #       uint32 ticket_age_add;
      #       opaque ticket_nonce<0..255>;
      #       opaque ticket<1..2^16-1>;
      #       Extension extensions<0..2^16-1>;
      #   } NewSessionTicket;
      #
      # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.1
      class NewSessionTicket < Message
        attr_accessor :ticket_lifetime
        attr_accessor :ticket_age_add
        attr_accessor :ticket_nonce
        attr_accessor :ticket
        attr_accessor :extensions

        # def initialize
        # end

        def self.deserialize(data)
          new_session_ticket = self.new
          buf = StringIO.new(data)
          new_session_ticket.ticket_lifetime = buf.read(4).unpack1("N")
          new_session_ticket.ticket_age_add = buf.read(4).unpack1("N")
          ticket_nonce_length = buf.read(1).unpack1("C")
          new_session_ticket.ticket_nonce = buf.read(ticket_nonce_length)
          ticket_length = buf.read(2).unpack1("n")
          new_session_ticket.ticket = buf.read(ticket_length)
          extensions_bytesize = buf.read(2).unpack1("n")
          new_session_ticket.extensions =
            Extension.deserialize_extensions(buf.read(extensions_bytesize), type: :new_session_ticket)

          new_session_ticket
        end
      end
    end
  end
end
