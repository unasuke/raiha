# frozen_string_literal: true

module Raiha::Next::QUIC
  class Streams
    # The sending part of a stream (RFC 9000 "Sending Stream States"): the
    # data the application wrote until it is acknowledged, the peer's limit
    # on the stream, and FIN.
    #
    # Frames are cut from what was lost first, then from what has not gone
    # yet, FIN with the last of the data or alone, and each comes back
    # acknowledged or lost as a Recovery::Duty::Stream. What was
    # acknowledged is not sent again, and the bytes up to the first that
    # was not are let go.
    #
    # Reset, it sends no more data and keeps none; RESET_STREAM goes with
    # the final size, the furthest it sent, until acknowledged.
    class Sender
      attr_reader :stream_id
      # The peer's limit on the stream (MAX_STREAM_DATA).
      attr_reader :limit
      # The bytes written: where the next write goes.
      attr_reader :written

      def initialize(stream_id:, limit:)
        @stream_id = stream_id
        @limit = limit
        # The bytes from `@base` on, every one before it acknowledged.
        @buffer = "".b
        @base = 0
        @written = 0
        @next_offset = 0
        @lost = [] #: Array[Range[Integer]]
        @acked = [] #: Array[Range[Integer]]
        # Whether the application ended the stream, FIN went in a frame not
        # known to be lost, and was acknowledged.
        @fin = false
        @fin_sent = false
        @fin_acked = false
        # The limit a STREAM_DATA_BLOCKED is due or went for.
        @blocked_at = nil #: Integer?
        @blocked_due = false
        # The error code of RESET_STREAM, whether it is due and was
        # acknowledged.
        @reset_code = nil #: Integer?
        @reset_due = false
        @reset_acked = false
      end

      # What the peer's limit leaves to write.
      def credit = @limit - @written

      # Whether the application has ended the stream.
      def fin? = @fin

      # Takes `data`, which the caller has made sure is within the limit,
      # and the end of the stream with `fin`.
      def write(data, fin:)
        @buffer << data
        @written += data.bytesize
        @fin = true if fin
      end

      # The peer's limit is `maximum` now; one that does not grow is no
      # news (RFC 9000 "Data Flow Control"). Whether it grew.
      def raise_limit(maximum)
        return false if maximum <= @limit
        @limit = maximum
        true
      end

      def pending? = !reset? && (!@lost.empty? || @next_offset < @written || (@fin && !@fin_sent))

      # The next frame and its duty in no more than `room` bytes, nil when
      # nothing waits or nothing fits.
      def next_frame(room)
        return nil if reset?
        range = @lost.first || (@next_offset...@written)
        return fin_frame(room) if Ranges.empty?(range)
        offset = range.begin
        header = 1 + Wire::Varint.size(@stream_id) + (offset.zero? ? 0 : Wire::Varint.size(offset)) + Wire::Varint.size(room)
        length = [range.end - offset, room - header].min
        return nil unless length.positive?
        if @lost.empty?
          @next_offset += length
        else
          rest = (offset + length)...range.end
          Ranges.empty?(rest) ? @lost.shift : @lost[0] = rest
        end
        fin = @fin && !@fin_sent && offset + length == @written
        @fin_sent = true if fin
        data = @buffer.byteslice(offset - @base, length) #: String
        [Wire::Frame::Stream.new(stream_id: @stream_id, offset:, data:, fin:), Recovery::Duty::Stream.new(stream_id: @stream_id, offset:, length:, fin:)]
      end

      # A frame was acknowledged: what it carried is not sent again. The
      # bytes let go, up to the first that was not acknowledged.
      def acked(offset, length, fin)
        @fin_acked = true if fin
        return 0 if length.zero? || reset?
        @acked = Ranges.add(@acked, offset...(offset + length))
        @lost = Ranges.subtract(@lost, offset...(offset + length))
        first = @acked.fetch(0)
        return 0 unless first.begin <= @base && first.end > @base
        released = first.end - @base
        @buffer = @buffer.byteslice(released..) #: String
        @base = first.end
        released
      end

      # A frame was lost: what of it was not acknowledged goes again.
      def lost(offset, length, fin)
        return if reset?
        @fin_sent = false if fin && !@fin_acked
        range = [offset, @base].max...(offset + length)
        return if Ranges.empty?(range)
        @lost = @acked.reduce([range]) { |left, acked| Ranges.subtract(left, acked) }.reduce(@lost) { |lost, part| Ranges.add(lost, part) }
      end

      # A write was cut short by the peer's limit: STREAM_DATA_BLOCKED
      # with it is due, once for each value of the limit.
      def blocked!
        return if @blocked_at == @limit
        @blocked_at = @limit
        @blocked_due = true
      end

      # Whether STREAM_DATA_BLOCKED with the limit is due.
      def blocked_due? = @blocked_due

      # STREAM_DATA_BLOCKED went: it is not due any more.
      def blocked_sent
        @blocked_due = false
      end

      # A STREAM_DATA_BLOCKED with `maximum` was lost: it goes again while
      # that limit still holds the stream back.
      def blocked_lost(maximum)
        @blocked_due = true if maximum == @limit && credit.zero?
      end

      def reset? = !@reset_code.nil?

      # The final size of a reset stream: the furthest it sent.
      def final_size = @next_offset

      # The application, or the peer's STOP_SENDING, abandons the stream
      # with `error_code`: RESET_STREAM is due, the data held is let go, and
      # what was written and never sent no longer counts. Nothing when it
      # was reset already or all of it was acknowledged. The bytes let go
      # and the bytes never sent.
      def reset!(error_code)
        return [0, 0] if reset? || all_acked?
        @reset_code = error_code
        @reset_due = true
        released = buffered
        unsent = @written - @next_offset
        @buffer = "".b
        @base = @written
        @lost = []
        [released, unsent]
      end

      # The error code of the RESET_STREAM due, nil when none is.
      def reset_due = @reset_due ? @reset_code : nil

      def reset_sent
        @reset_due = false
      end

      def reset_acked
        @reset_acked = true
      end

      # RESET_STREAM was lost: it goes again until acknowledged.
      def reset_lost
        @reset_due = true unless @reset_acked
      end

      # The bytes held: written and not acknowledged.
      def buffered = @written - @base

      # Whether all of the stream, FIN too, was acknowledged (Data Recvd).
      def all_acked? = @fin_acked && @base == @written

      # FIN alone, once all the data has gone.
      private def fin_frame(room)
        return nil unless @fin && !@fin_sent
        header = 1 + Wire::Varint.size(@stream_id) + (@written.zero? ? 0 : Wire::Varint.size(@written)) + 1
        return nil if header > room
        @fin_sent = true
        [Wire::Frame::Stream.new(stream_id: @stream_id, offset: @written, data: "".b, fin: true),
          Recovery::Duty::Stream.new(stream_id: @stream_id, offset: @written, length: 0, fin: true)]
      end
    end
  end
end
