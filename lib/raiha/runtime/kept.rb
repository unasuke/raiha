# frozen_string_literal: true

module Raiha::Runtime
  # What a client keeps of what the server gave for later connections: the
  # tickets of SessionTicket events and the tokens of NewToken ones, the
  # newest MAX_HELD of each, newest last, so that a server sending them
  # without end cannot make the client keep them all. A ticket dropped so is
  # told to the connection's `tracer`. A Session of fibers and one of
  # threads keep them alike.
  class Kept
    MAX_HELD = 8

    def initialize(tracer)
      @tracer = tracer
      @tickets = [] #: Array[Raiha::QUIC::Session]
      @tokens = [] #: Array[String]
    end

    def tickets = @tickets.dup

    def tokens = @tokens.dup

    def ticket(session)
      if @tickets.size >= MAX_HELD
        @tickets.shift
        @tracer&.tls_trace(Raiha::TLS::Trace::TicketIgnored.new(reason: :too_many_tickets))
      end
      @tickets << session
    end

    def token(token)
      @tokens.shift if @tokens.size >= MAX_HELD
      @tokens << token
    end
  end
end
