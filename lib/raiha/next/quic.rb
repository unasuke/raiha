# frozen_string_literal: true

require_relative "tls"

# QUIC. May refer to the TLS layer.
module Raiha::Next::QUIC
end

require_relative "quic/error"
require_relative "quic/error_code"
require_relative "quic/transmit"
require_relative "quic/event"
