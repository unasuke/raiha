# frozen_string_literal: true

require_relative "../tls"

# Test support shipped with the gem. `require "raiha/tls"` does not load
# it; use `require "raiha/tls/test"`.
module Raiha::Next::TLS::Test
end

require_relative "test/rfc8448"
require_relative "test/fixed_kem"
require_relative "test/fixed_random"
require_relative "test/rfc8448_handshakes"
