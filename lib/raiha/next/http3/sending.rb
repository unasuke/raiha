# frozen_string_literal: true

module Raiha::Next::HTTP3
  # The sending side of one request stream, as far as the application has
  # written: :headers until the header section of its message, which
  # interim responses may come before, :body after it.
  class Sending
    attr_accessor :phase
    # Whether a write took less than given, so that the application hears
    # when the stream takes more.
    attr_accessor :wants_writable
    # Whether the request has a use for HTTP Datagrams.
    attr_accessor :datagrams

    def initialize
      @phase = :headers #: :headers | :body
      @wants_writable = false
      @datagrams = false
    end
  end
end
