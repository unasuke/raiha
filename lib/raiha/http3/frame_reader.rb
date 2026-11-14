# frozen_string_literal: true

require_relative "frame"

module Raiha::HTTP3
  # Reads the frames of one stream from its bytes as they come, without
  # trusting a length to set aside room first (RFC 9114 "Frame Layout").
  #
  # Each frame tells it began, with its type and length, as soon as both
  # are known, so that a frame the stream must not carry is refused before
  # its payload comes. A DATA frame then comes in the pieces it arrives in,
  # never held; a frame of the other types this layer reads is held until
  # whole and comes decoded, unless its length is past `max_payload`, when
  # it is told so and its payload passed over. The payloads of the frame
  # types of HTTP/2 and of types unknown are passed over as they come.
  class FrameReader
    # A frame began.
    class Started < Data.define(:type, :length); end

    # A frame of a type that is held is longer than `max_payload`.
    class TooLong < Data.define(:type, :length); end

    HELD = [
      Frame::HEADERS, Frame::CANCEL_PUSH, Frame::SETTINGS, Frame::PUSH_PROMISE, Frame::GOAWAY, Frame::MAX_PUSH_ID,
      Frame::PRIORITY_UPDATE, Frame::PRIORITY_UPDATE_PUSH
    ].freeze
    # The longest a type and a length take together.
    MAX_HEADER = 16

    def initialize(max_payload:)
      @max_payload = max_payload
      # The start of a type and length cut short, and the frame being read:
      # its type, the bytes of it to come, and whether it is held, passed
      # on as it comes, or passed over.
      @header = "".b
      @type = nil #: Integer?
      @left = 0
      @mode = :skip #: :hold | :pass | :skip
      @payload = "".b
    end

    # Whether the bytes so far end inside a frame, which is H3_FRAME_ERROR
    # if the stream ends there (RFC 9114 "Frame Layout").
    def mid_frame? = !@header.empty? || !@type.nil?

    # Reads `bytes`, yielding a Started for each frame that begins, the
    # pieces of DATA frames as Frame::Data, other frames whole, and a
    # TooLong for each held frame past `max_payload`. A payload that does
    # not decode raises Frame::Malformed.
    def feed(bytes, &)
      offset = 0
      while offset < bytes.bytesize
        offset = @type ? read_payload(bytes, offset, &) : read_header(bytes, offset, &)
      end
    end

    private def read_header(bytes, offset, &)
      held = @header.bytesize
      if held.zero?
        source = bytes
        start = offset
      else
        source = @header << bytes.byteslice(offset, MAX_HEADER - held) # steep:ignore
        start = 0
      end
      type, after = Varint.decode(source, start)
      length, after = Varint.decode(source, after) if type && after
      unless length && after
        @header = source.byteslice(start..) if held.zero?
        return bytes.bytesize
      end
      @header = "".b
      begin_frame(type, length, &) # steep:ignore
      held.zero? ? after : offset + after - held
    end

    private def begin_frame(type, length, &)
      yield Started.new(type:, length:)
      @type = type
      @left = length
      @mode = if type == Frame::DATA
        :pass
      elsif HELD.include?(type) && length <= @max_payload
        :hold
      else
        yield TooLong.new(type:, length:) if HELD.include?(type)
        :skip
      end
      return unless length.zero?
      yield Frame::Data.new(data: "") if @mode == :pass
      finish_frame(&)
    end

    private def read_payload(bytes, offset, &)
      taken = [@left, bytes.bytesize - offset].min
      case @mode
      when :pass then yield Frame::Data.new(data: bytes.byteslice(offset, taken).freeze) # steep:ignore
      when :hold then @payload << bytes.byteslice(offset, taken) # steep:ignore
      end
      @left -= taken
      finish_frame(&) if @left.zero?
      offset + taken
    end

    private def finish_frame
      type = @type or return
      payload = @payload
      held = @mode == :hold
      @type = nil
      @payload = "".b
      yield Frame.decode(type, payload.freeze) if held
    end
  end
end
