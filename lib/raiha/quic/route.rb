# frozen_string_literal: true

module Raiha::Next::QUIC
  # What an Endpoint did with a datagram it received.
  module Route
    # Given to the connection it belongs to.
    class Deliver < Data.define(:connection)
    end

    # The first stage of a new connection, from what the headers of a
    # client's first Initial alone say: the application `retry`s, `refuse`s
    # or `admit`s `handle`, and can retry it at this stage alone. `address_validated` is whether a token showed
    # the client receives at `remote`.
    class Incoming < Data.define(:handle, :remote, :address_validated)
    end

    # The second stage: the ClientHello of `handle` is whole. `accepted` is
    # the TLS layer's Handshake::Accepted, unauthenticated, which the
    # application picks a TLS Config by before it `accept`s.
    class ClientHello < Data.define(:handle, :accepted)
    end

    # A datagram the Endpoint answers itself, with nothing kept: a Version
    # Negotiation, a Stateless Reset, or a CONNECTION_CLOSE for a Retry
    # token that does not verify.
    class Respond < Data.define(:transmit)
    end

    # For another worker, whose connection ID it has.
    class Foreign < Data.define(:worker, :datagram)
    end

    # Dropped, for `reason`.
    class Drop < Data.define(:reason)
    end
  end
end
