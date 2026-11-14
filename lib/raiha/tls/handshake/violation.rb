# frozen_string_literal: true

module Raiha::TLS
  module Handshake
    # The first check a message fails on its own, without knowing what was
    # sent, the configuration or the role: the alert to send and a Symbol
    # naming the check. Checks that need that context belong to the state
    # machine.
    class Violation < Data.define(:alert, :reason)
    end
  end
end
