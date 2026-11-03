# frozen_string_literal: true

module Raiha::Next::QUIC
  # Congestion control, one controller a path. Loss recovery tells it what
  # was sent, acknowledged and lost, and asks it for the window; it keeps no
  # count of the bytes in flight and does not detect losses itself.
  module Congestion
  end
end

require_relative "congestion/pacing"
require_relative "congestion/new_reno"
require_relative "congestion/cubic"
require_relative "congestion/algorithms"
