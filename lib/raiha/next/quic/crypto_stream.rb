# frozen_string_literal: true

module Raiha::Next::QUIC
  # The CRYPTO frames of one encryption level (RFC 9000 "CRYPTO Frames").
  #
  # Sending, the bytes TLS writes stay until acknowledged; frames are cut
  # from what was lost first, then from what has not gone yet, and each
  # range acknowledged or lost comes back as a Recovery::Duty::Crypto.
  #
  # Receiving, frames are put back in order and handed on as far as the
  # bytes run without a gap. What waits, from what has been read up to the
  # end of the furthest frame, must stay within the limit given, or the
  # connection fails with CRYPTO_BUFFER_EXCEEDED (RFC 9000 "Cryptographic
  # Message Buffering").
  class CryptoStream
    FRAME_TYPE = 0x06

    # The number space the level's packets are in.
    attr_reader :space
    # The end of the furthest frame received.
    attr_reader :received_end
    # How far the bytes received have been read.
    attr_reader :read_offset

    def initialize(space)
      @space = space
      @sent = "".b
      @sent_base = 0
      @next_offset = 0
      @lost = [] #: Array[Range[Integer]]
      @acked = [] #: Array[Range[Integer]]
      @segments = {} #: Hash[Integer, String]
      @received_end = 0
      @read_offset = 0
    end

    # Bytes of TLS to send.
    def write(bytes) = @sent << bytes

    def pending? = !@lost.empty? || @next_offset < send_end

    # The next frame, and its duty, in no more than `room` bytes: from what
    # was lost first, then from what has not gone yet. nil when nothing waits
    # or nothing fits.
    def next_frame(room)
      range = @lost.first || (@next_offset...send_end)
      return nil if empty?(range)
      offset = range.begin
      length = [range.end - offset, room - 1 - Wire::Varint.size(offset) - Wire::Varint.size(room)].min
      return nil unless length.positive?
      if @lost.empty?
        @next_offset += length
      else
        rest = (offset + length)...range.end
        empty?(rest) ? @lost.shift : @lost[0] = rest
      end
      data = @sent.byteslice(offset - @sent_base, length) #: String
      [Wire::Frame::Crypto.new(offset:, data:), Recovery::Duty::Crypto.new(space: @space, offset:, length:)]
    end

    # A range sent was acknowledged: it is not sent again, and the bytes up
    # to the first gap are let go.
    def acked(offset, length)
      @acked = add(@acked, offset...(offset + length))
      @lost = subtract(@lost, offset...(offset + length))
      first = @acked.first or return
      return unless first.begin <= @sent_base && first.end > @sent_base
      @sent = @sent.byteslice((first.end - @sent_base)..) #: String
      @sent_base = first.end
    end

    # A range sent was lost: what of it is not acknowledged goes again.
    def lost(offset, length)
      range = [offset, @sent_base].max...(offset + length)
      return if empty?(range)
      @lost = @acked.reduce([range]) { |left, acked| subtract(left, acked) }.reduce(@lost) { |lost, part| add(lost, part) }
    end

    # Bytes received at `offset`, kept until read; a Violation of
    # CRYPTO_BUFFER_EXCEEDED when more than `limit` bytes would wait.
    def receive(offset, data, limit:)
      finish = offset + data.bytesize
      return if finish <= @read_offset
      if finish - @read_offset > limit
        raise Violation.new("#{finish - @read_offset} CRYPTO bytes waiting, over #{limit}", code: ErrorCode::CRYPTO_BUFFER_EXCEEDED,
          frame_type: FRAME_TYPE)
      end
      if offset < @read_offset
        data = data.byteslice((@read_offset - offset)..) #: String
        offset = @read_offset
      end
      @segments[offset] = data unless (@segments[offset]&.bytesize || -1) >= data.bytesize
      @received_end = finish if finish > @received_end
    end

    # The bytes received from where reading stopped up to the first gap.
    def read
      out = "".b
      while (start, data = @segments.find { |start, data| start <= @read_offset && start + data.bytesize > @read_offset })
        out << data.byteslice((@read_offset - start)..) # steep:ignore
        @read_offset = start + data.bytesize
      end
      @segments.delete_if { |start, data| start + data.bytesize <= @read_offset }
      out
    end

    # How many bytes wait to be read, counted to the end of the furthest
    # frame.
    def buffered = @received_end - @read_offset

    private def send_end = @sent_base + @sent.bytesize

    private def empty?(range) = range.begin >= range.end

    # `ranges` with `range` added, merged, in order.
    private def add(ranges, range)
      merged = ranges + [range]
      merged.sort_by!(&:begin)
      merged.each_with_object([]) do |part, result|
        last = result.last
        if last && part.begin <= last.end
          result[-1] = last.begin...[last.end, part.end].max
        else
          result << part
        end
      end
    end

    # `ranges` without `range`.
    private def subtract(ranges, range)
      ranges.flat_map do |part|
        [part.begin...[part.end, range.begin].min, [part.begin, range.end].max...part.end].reject { |piece| empty?(piece) }
      end
    end
  end
end
