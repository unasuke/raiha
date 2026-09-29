# frozen_string_literal: true

require_relative "../tls"

# Test support shipped with the gem. `require "raiha/next/tls"` does not load
# it; use `require "raiha/next/tls/test"`.
module Raiha::Next::TLS::Test
end

require_relative "test/rfc8448"
