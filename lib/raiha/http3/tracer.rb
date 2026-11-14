# frozen_string_literal: true

module Raiha::HTTP3
  # What an HTTP/3 connection tells of itself as it goes, for a qlog or
  # anything else: a tracer includes this and overrides what it wants;
  # what it does not is ignored.
  #
  # `initiator` is :local or :remote. A frame comes with its `type` and
  # the `length` of its payload, nil where the frame is written whole;
  # with `frame`, the frame itself, for those of the control stream and
  # PRIORITY_UPDATE; and with `headers`, a field section as [name, value]
  # pairs, for HEADERS. Nothing here is copied for the tracer: what it
  # keeps, it copies.
  module Tracer
    def parameters_set(initiator:, settings:) = nil

    # `type` is a stream type, or :request for a request stream.
    def stream_type_set(initiator:, stream_id:, type:) = nil

    def frame_created(stream_id:, type:, length: nil, frame: nil, headers: nil) = nil

    def frame_parsed(stream_id:, type:, length: nil, frame: nil, headers: nil) = nil

    def priority_updated(stream_id:, priority:) = nil
  end
end
