# frozen_string_literal: true

require_relative "error_code"

module Raiha::Next::QUIC
  # Exceptions are for misuse of the API only. What the peer does never
  # raises: a protocol error is a ConnectionError value, sent as
  # CONNECTION_CLOSE and reported in Event::Closed.
  module Error
    class Base < StandardError; end

    # A call the API does not allow, as writing to a closed connection.
    class Usage < Base; end

    # A call in a state that does not allow it.
    class StateError < Usage; end

    # A call on a stream that does not exist or does not allow it.
    class StreamError < Usage; end
  end

  # The peer broke a rule of the protocol. `code` is the transport error to
  # close the connection with, and `frame_type` the type of the frame that
  # broke it, when one did. Raised inside the layer and turned into a
  # ConnectionError where the input came in; the application never sees it.
  class Violation < StandardError
    attr_reader :code
    attr_reader :frame_type

    def initialize(message = nil, code: ErrorCode::PROTOCOL_VIOLATION, frame_type: nil)
      super(message)
      @code = code
      @frame_type = frame_type
    end
  end

  # Why a connection closed: a transport error code (ErrorCode) or an
  # application's, the type of the frame that caused it (nil when none or an
  # application error), and a reason phrase.
  class ConnectionError < Data.define(:code, :frame_type, :reason, :application)
  end

  # The connection closed under a call that waited on it or came after, as
  # an I/O layer that blocks for the application raises it; `error` is the
  # ConnectionError it closed with. It is no misuse of the API: the peer
  # or the network can close a connection at any time.
  class ClosedError < StandardError
    attr_reader :error

    def initialize(error)
      @error = error
      kind = error.application ? "application" : "transport"
      super(format("closed with %s error 0x%x%s", kind, error.code, error.reason.empty? ? "" : ": #{error.reason}"))
    end
  end
end
