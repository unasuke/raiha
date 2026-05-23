require_relative "../../../util/io_reader"

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

        def initialize
          @ticket_lifetime = 0
          @ticket_age_add = 0
          @ticket_nonce = ""
          @ticket = ""
          @extensions = []
        end

        def self.deserialize(data)
          new_session_ticket = self.new
          buf = StringIO.new(data)
          new_session_ticket.ticket_lifetime = Raiha::Util::IOReader.read_exact(buf, 4).unpack1("N")
          new_session_ticket.ticket_age_add = Raiha::Util::IOReader.read_exact(buf, 4).unpack1("N")
          ticket_nonce_length = Raiha::Util::IOReader.read_exact(buf, 1).unpack1("C")
          new_session_ticket.ticket_nonce = Raiha::Util::IOReader.read_exact(buf, ticket_nonce_length)
          ticket_length = Raiha::Util::IOReader.read_exact(buf, 2).unpack1("n")
          new_session_ticket.ticket = Raiha::Util::IOReader.read_exact(buf, ticket_length)
          extensions_bytesize = Raiha::Util::IOReader.read_exact(buf, 2).unpack1("n")
          new_session_ticket.extensions =
            Extension.deserialize_extensions(Raiha::Util::IOReader.read_exact(buf, extensions_bytesize), type: :new_session_ticket)

          new_session_ticket
        end

        def serialize
          buf = String.new(encoding: "BINARY")
          buf << [@ticket_lifetime].pack("N")
          buf << [@ticket_age_add].pack("N")
          buf << [@ticket_nonce.bytesize].pack("C")
          buf << @ticket_nonce
          buf << [@ticket.bytesize].pack("n")
          buf << @ticket
          ext_buf = @extensions.map(&:serialize).join
          buf << [ext_buf.bytesize].pack("n")
          buf << ext_buf
          buf
        end
      end
    end
  end
end
