# frozen_string_literal: true

module Raiha::Next::TLS
  # TLS over TCP: the handshake core with the record layer, without I/O
  # (Connection).
  module TCP
  end
end

require_relative "tcp/event"
require_relative "tcp/connection"
