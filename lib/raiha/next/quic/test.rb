# frozen_string_literal: true

require_relative "../quic"

# Test support shipped with the gem. `require "raiha/next/quic"` does not
# load it; use `require "raiha/next/quic/test"`.
module Raiha::Next::QUIC::Test
end

require_relative "test/vectors"
require_relative "test/congestion_contract"
require_relative "test/virtual_clock"
require_relative "test/network"
require_relative "test/random_loss"
require_relative "test/reorder"
require_relative "test/bottleneck"
