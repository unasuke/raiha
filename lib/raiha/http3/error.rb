# frozen_string_literal: true

require_relative "error_code"

module Raiha::HTTP3
  # Exceptions are for misuse of the API only. What the peer sends never
  # raises; it closes the connection, or resets a stream.
  module Error
    # A call the API does not allow, as data for a stream already ended.
    class Usage < StandardError; end
  end

  # The peer broke a rule that closes the connection with `code`, an
  # ErrorCode. Raised inside this layer and turned into the closing of the
  # connection where the bytes came in; the application never sees it.
  class Violation < StandardError
    attr_reader :code

    def initialize(message = nil, code:)
      super(message)
      @code = code
    end
  end
end
