# frozen_string_literal: true

require "openssl"

module Raiha::TLS
  # Decides whether the peer's certificate chain is acceptable.
  #
  # A verifier answers `verify(chain:, server_name:, now:, purpose:)` with a
  # Result, and `resumption_policy` with a String that changes whenever what
  # it accepts changes (nil if it cannot say). A failure is a Result, never
  # an exception: the chain comes from the peer, so an exception would be one
  # the peer can raise. An exception that escapes anyway is not caught; the
  # handshake forgets its secrets, fails and lets it through.
  module Verifier
    # `reason` is the alert to send when `ok` is false. `verified_chain` is
    # the chain as verified, leaf first.
    class Result < Data.define(:ok, :reason, :verified_chain)
    end
  end
end

require_relative "verifier/host_name"
require_relative "verifier/default"
require_relative "verifier/none"
