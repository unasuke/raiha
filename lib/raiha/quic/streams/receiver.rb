# frozen_string_literal: true

module Raiha::QUIC
  class Streams
    # The receiving part of a stream (RFC 9000 "Receiving Stream States"):
    # its receive window, the data received but not read, and the final
    # size once known.
    #
    # Abandoned, when the application stops reading or the peer resets the
    # stream, it keeps no data: what was received and not read is
    # consumed, and so is what comes after, so that the credit goes back
    # (flow control's design, "Accounting").
    #
    # Data waits as ranges that neither overlap nor touch, in order, each
    # in a String of the stream's own, so that nothing of a datagram is
    # kept; a range is found with `bsearch_index` and joined to those it
    # touches. The holes before the furthest range, from where the
    # application has read, are counted, so that the connection can keep
    # their number down.
    class Receiver
      # Data received, from `offset` on.
      class Chunk
        attr_accessor :offset, :data

        def initialize(offset, data)
          @offset = offset
          @data = data
        end

        def end_offset = offset + data.bytesize
      end

      attr_reader :window
      # The final size, nil until a frame with FIN tells it.
      attr_reader :final_size
      # How far the application has read.
      attr_reader :read_offset

      def initialize(window:)
        @window = window
        @ranges = [] #: Array[Chunk]
        @read_offset = 0
        @final_size = nil #: Integer?
        @stopped = false
        @reset = false
        # Whether a read gave the end.
        @end_read = false
        # The error code of the STOP_SENDING the application asked for, and
        # whether it is due.
        @stop_code = nil #: Integer?
        @stop_due = false
      end

      # Takes the end of a frame of `frame_type` that ends at `end_offset`,
      # with FIN or not, before any of its data is kept: FINAL_SIZE_ERROR
      # when it does not keep to the final size, known or now told, then
      # FLOW_CONTROL_ERROR past the stream's limit (RFC 9000 "Stream Final
      # Size"). The bytes the stream has been received further by, which
      # the connection's window takes.
      def admit(end_offset, fin:, frame_type:)
        if (final = @final_size)
          if end_offset > final || (fin && end_offset != final)
            raise Violation.new("data up to #{end_offset} of a stream of #{final} bytes", code: ErrorCode::FINAL_SIZE_ERROR, frame_type:)
          end
        elsif fin && end_offset < @window.received
          raise Violation.new("a final size of #{end_offset} under #{@window.received} received", code: ErrorCode::FINAL_SIZE_ERROR,
            frame_type:)
        end
        before = @window.received
        @window.receive(end_offset, frame_type:)
        @final_size = end_offset if fin
        @window.received - before
      end

      # The holes there would be with `length` bytes at `offset` too.
      def gaps_with(offset, length)
        start, finish = clip(offset, length)
        return gaps if finish <= start
        first, last = touching(start, finish)
        count = @ranges.size - (last - first) + 1
        head = first.zero? ? [start, @ranges.first&.offset || start].min : @ranges.fetch(0).offset
        count - (head == @read_offset ? 1 : 0)
      end

      def gaps
        return 0 if @ranges.empty?
        @ranges.size - (@ranges.fetch(0).offset == @read_offset ? 1 : 0)
      end

      # Keeps `data` at `offset`, admitted, as far as it was not read or
      # received before; what was received before stays. The ranges it
      # touches become one: the first goes on growing when the data starts
      # in it, which is how data in order comes.
      def insert(offset, data)
        start, finish = clip(offset, data.bytesize)
        return if finish <= start
        first, last = touching(start, finish)
        joined = @ranges[first, last - first] || []
        head = joined.first
        if head && head.offset <= start
          joined = joined.drop(1)
          chunk = head
        else
          chunk = Chunk.new(start, "".b)
        end
        # Ranges never touch, so data received fills what lies between.
        joined.each do |range|
          between = data.byteslice(chunk.end_offset - offset, range.offset - chunk.end_offset) #: String
          chunk.data << between << range.data
        end
        if chunk.end_offset < finish
          rest = data.byteslice(chunk.end_offset - offset, finish - chunk.end_offset) #: String
          chunk.data << rest
        end
        @ranges[first, last - first] = [chunk]
      end

      # Up to `max_bytes` of the data that runs on from what was read, ""
      # when none does yet, and nil once all of it up to the final size
      # has been read, as IO#read has it at the end of a file. What is read
      # is consumed in the receive window.
      def read(max_bytes)
        head = @ranges.first
        if head && head.offset == @read_offset
          chunk = head.data.byteslice(0, max_bytes) #: String
          if chunk.bytesize == head.data.bytesize
            @ranges.shift
          else
            head.data = head.data.byteslice(chunk.bytesize..) # steep:ignore
            head.offset += chunk.bytesize
          end
          @read_offset += chunk.bytesize
          @window.consume(chunk.bytesize)
          return chunk
        end
        if @final_size == @read_offset
          @end_read = true
          return nil
        end
        "".b
      end

      # The application stops reading with `error_code`: STOP_SENDING is
      # due, and what was received and not read is consumed. The bytes
      # consumed.
      def stop!(error_code)
        return 0 if @stopped || @reset
        @stopped = true
        @stop_code = error_code
        @stop_due = true
        drop_to(@window.received)
      end

      # The peer reset the stream at `final_size`, admitted: what was not
      # read up to it is consumed. The bytes consumed.
      def reset!(final_size)
        @reset = true
        @final_size = final_size
        @stop_due = false
        drop_to(final_size)
      end

      def reset? = @reset

      # Whether the stream is over here: read to its final size, or reset.
      def finished? = @final_size == @read_offset

      # Whether the stream keeps no data any more.
      def abandoned? = @stopped || @reset

      # Data admitted to an abandoned stream is consumed as it comes. The
      # bytes consumed.
      def discard = drop_to(@window.received)

      # The error code of the STOP_SENDING due, nil when none is.
      def stop_due = @stop_due ? @stop_code : nil

      # STOP_SENDING went.
      def stop_sent
        @stop_due = false
      end

      # STOP_SENDING was lost: it goes again unless the peer has reset the
      # stream since, or sent all of it.
      def stop_lost
        @stop_due = true unless @reset || (@final_size && @window.received == @final_size)
      end

      # Whether a read gives anything: data, or the end not read yet.
      def readable?
        head = @ranges.first
        (head && head.offset == @read_offset) || (@final_size == @read_offset && !@end_read)
      end

      # The data up to `offset` is consumed, and none is kept: the bytes
      # consumed.
      private def drop_to(offset)
        consumed = [offset - @read_offset, 0].max
        @ranges.clear
        @read_offset += consumed
        @window.consume(consumed)
        consumed
      end

      # `offset` and `length` cut to what is past the read data.
      private def clip(offset, length) = [[offset, @read_offset].max, offset + length]

      # The indices of the ranges that overlap or touch start...finish:
      # first...last.
      private def touching(start, finish)
        first = @ranges.bsearch_index { |range| range.end_offset >= start } || @ranges.size
        last = @ranges.bsearch_index { |range| range.offset > finish } || @ranges.size
        [first, last]
      end
    end
  end
end
