# frozen_string_literal: true

module Raiha::Next::TLS
  # TLS over TCP: the handshake core with the record layer, without I/O
  # (Connection, and Acceptor for a server that picks its Config by the
  # ClientHello), and over a socket (Socket).
  module TCP
  end
end

require_relative "tcp/event"
require_relative "tcp/acceptor"
require_relative "tcp/connection"
require_relative "tcp/socket"
