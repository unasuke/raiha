# frozen_string_literal: true

require_relative "frame_reader"

module Raiha::Next::HTTP3
  # The receiving side of one request stream: its frames, how far the
  # message has come, and what waits while its field section is blocked
  # on the QPACK encoder stream.
  class Receiving
    attr_reader :reader, :waiting
    # The bytes of DATA among what waits.
    attr_accessor :waiting_bytes
    # :headers until the field section has come, :blocked while it waits
    # on QPACK, :body after it.
    attr_accessor :phase
    # Whether the stream ended, while blocked.
    attr_accessor :fin_waiting

    def initialize(max_payload:)
      @reader = FrameReader.new(max_payload:)
      @phase = :headers #: :headers | :blocked | :body
      @waiting = [] #: Array[FrameReader::item]
      @waiting_bytes = 0
      @fin_waiting = false
    end

    def blocked? = @phase == :blocked
  end
end
