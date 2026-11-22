# frozen_string_literal: true

require "socket"

module Raiha::Runtime
  # How a client of the runtime finds the addresses of a host, and the
  # socket it tries each from, apart from how it waits for the handshake.
  # A client of fibers and one of threads try them alike.
  module Addresses
    # [address, port] of `host` for UDP, each once, in the order the
    # resolver gives them; an IPv4-mapped address as the IPv4 address it
    # maps, which a socket of IPv6 alone cannot send to.
    def self.resolve(host, port)
      Addrinfo.getaddrinfo(host, port, nil, :DGRAM).map do |info|
        [UDP.unmapped(info.ip_address), info.ip_port] #: UDP::address
      end.uniq
    end

    # A socket for a connection to `address`, and `config` for the address
    # families it can send to: one bound to "::", which sends to IPv4 too,
    # unless IPv4 does not come to it, when it is kept for IPv6 alone; for
    # IPv4 then, and where "::" cannot be bound, one bound to "0.0.0.0".
    def self.bind(address, config)
      udp = UDP.bind("::", 0)
      return [udp, config] if udp.takes_ipv4?
      return [udp, config.with(address_families: %i[ipv6])] if address[0].include?(":")
      udp.close
      [UDP.bind("0.0.0.0", 0), config.with(address_families: %i[ipv4])]
    rescue SystemCallError
      # Without "::" there is no IPv6 to send to `address` by.
      raise if address[0].include?(":")
      [UDP.bind("0.0.0.0", 0), config.with(address_families: %i[ipv4])]
    end
  end
end
