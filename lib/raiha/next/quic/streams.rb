# frozen_string_literal: true

module Raiha::Next::QUIC
  # The streams of a connection and their flow control (RFC 9000 "Streams"
  # and "Flow Control").
  class Streams
  end
end

require_relative "streams/receive_window"
require_relative "streams/receiver"
