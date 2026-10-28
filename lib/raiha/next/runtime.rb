# frozen_string_literal: true

require_relative "tls"
require_relative "quic"
require_relative "http3"

# The I/O runtime (Fiber, Ractor, Socket). May refer to TLS, QUIC and HTTP/3.
module Raiha::Next::Runtime
end

require_relative "runtime/error"
require_relative "runtime/udp"
require_relative "runtime/driver"
require_relative "runtime/session"
require_relative "runtime/client"
require_relative "runtime/server"
