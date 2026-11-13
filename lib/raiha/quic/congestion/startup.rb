# frozen_string_literal: true

module Raiha::QUIC
  module Congestion
    # The parts that wrap a path's controller while the connection starts,
    # in place of its slow start, and hand it back for the rest
    # (Config#startup).
    module Startup
    end
  end
end

require_relative "startup/rapid_start"
