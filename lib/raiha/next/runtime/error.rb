# frozen_string_literal: true

module Raiha::Next::Runtime
  # Misuse of the runtime. What the peer or the network does to a
  # connection comes as QUIC::ClosedError instead.
  module Error
    class Base < StandardError; end

    # A call the runtime does not allow, as one with no Fiber scheduler.
    class Usage < Base; end
  end
end
