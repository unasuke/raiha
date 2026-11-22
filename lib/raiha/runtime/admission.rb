# frozen_string_literal: true

module Raiha::Runtime
  # What a server of the runtime decides of the clients that come, apart
  # from how it waits: whether to take one, how many addresses are not
  # validated yet, and the ticket keys of the next connection. A server of
  # fibers and one of threads decide alike.
  module Admission
    # What to do with an Incoming `route`: :refuse once the server is
    # `full`, :retry when the client's address is not validated and the
    # block, how many are not, has reached `max_unvalidated`, :admit
    # otherwise. The block is called only when the address is not
    # validated.
    def self.decide(route, full:, max_unvalidated:)
      return :refuse if full
      return :retry if !route.address_validated && yield >= max_unvalidated
      :admit
    end

    # How many of the offers `admitted` and of the `connections` taken have
    # addresses not validated, the offers over left out.
    def self.unvalidated(admitted, connections, now)
      admitted.count { |handle| !handle.expired?(now) && !handle.failed? } + connections.count { |connection| !connection.address_validated? }
    end

    # The Keyring for the connections from `time` on, with the ticket keys
    # of `tls_config` built again once their epoch is over (a
    # TicketKeys.ratchet); nil while they stay. A `keyring` of another
    # Config is left for the handshake to refuse.
    def self.advance_ticket_keys(tls_config, keyring, time)
      keys = tls_config.ticket_keys or return nil
      at = keys.next_advance_at or return nil
      return nil if time < at || !keyring.config.equal?(tls_config)
      keyring.with_ticket_keys(keys.advance(now: time))
    end
  end
end
