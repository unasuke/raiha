# frozen_string_literal: true

require_relative "error_code"

module Raiha::Next::HTTP3::QPACK
  # The peer broke a rule of QPACK: `code` is the ErrorCode to close the
  # connection with, or to reset the stream `stream_id` with when there is
  # one (RFC 9204 "Implementation Limits"), and `reason` says what broke.
  class Failure < Data.define(:code, :reason, :stream_id)
    def initialize(code:, reason:, stream_id: nil) = super
  end
end
