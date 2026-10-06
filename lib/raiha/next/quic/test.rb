# frozen_string_literal: true

require_relative "../quic"

# Test support shipped with the gem. `require "raiha/next/quic"` does not
# load it; use `require "raiha/next/quic/test"`.
module Raiha::Next::QUIC::Test
end

require_relative "test/vectors"
