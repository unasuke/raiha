# frozen_string_literal: true

require_relative "frame_reader"

module Raiha::Next::HTTP3
  # The receiving side of one request stream: its frames, how far the
  # message has come, and what waits while a field section of it is
  # blocked on the QPACK encoder stream.
  class Receiving
    attr_reader :reader, :waiting
    # The frames seen: :headers until a HEADERS frame, :body after it, and
    # :trailers after a second one.
    attr_accessor :phase
    # Whether a field section waits on QPACK; and behind it, the bytes of
    # the DATA and field sections waiting, and whether the stream ended.
    attr_accessor :blocked, :waiting_bytes, :fin_waiting
    # Whether the application has the header section; the Content-Length
    # it gave, the bytes of DATA so far, and what the trailers may take of
    # the limit on field sections.
    attr_accessor :surfaced, :content_length, :received, :budget

    def initialize(max_payload:)
      @reader = FrameReader.new(max_payload:)
      @phase = :headers #: :headers | :body | :trailers
      @blocked = false
      @waiting = [] #: Array[FrameReader::item]
      @waiting_bytes = 0
      @fin_waiting = false
      @surfaced = false
      @content_length = nil #: Integer?
      @received = 0
      @budget = 0
    end
  end
end
