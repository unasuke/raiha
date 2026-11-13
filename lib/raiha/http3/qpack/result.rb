# frozen_string_literal: true

require_relative "error_code"

module Raiha::Next::HTTP3::QPACK
  # A field section decoded: its fields in order, and their size as RFC
  # 9114 "Header Size Constraints" counts it, name and value and 32 more
  # for each.
  class Decoded < Data.define(:stream_id, :fields, :size); end

  # A field section that refers to entries yet to come on the encoder
  # stream (RFC 9204 "Blocked Decoding"); it comes out decoded once they
  # do.
  class Blocked < Data.define(:stream_id); end

  # A field section whose fields grew past the budget, at which the
  # decoder stopped.
  class Oversized < Data.define(:stream_id); end

  # The peer broke a rule of QPACK: `code` is the ErrorCode to close the
  # connection with, or to reset the stream `stream_id` with when there is
  # one (RFC 9204 "Implementation Limits"), and `reason` says what broke.
  class Failure < Data.define(:code, :reason, :stream_id)
    def initialize(code:, reason:, stream_id: nil) = super
  end
end
