# frozen_string_literal: true

module Raiha::Runtime
  # Misuse of the runtime. What the peer or the network does to a
  # connection comes as QUIC::ClosedError instead.
  module Error
    class Base < StandardError; end

    # A call the runtime does not allow, as one with no Fiber scheduler.
    class Usage < Base; end

    # A part of the runtime that runs on its own, as the record of 0-RTT
    # the workers of Workers share, stopped before it was told to.
    class Stopped < Base; end
  end
end
