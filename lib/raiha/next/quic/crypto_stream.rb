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
  # Message Buffering"). The bytes wait in one buffer of that span, however
  # the frames overlap, and the ranges received in at most MAX_RANGES
  # pieces, as quic-go's frame sorter keeps to 1000 gaps
  # (`MaxStreamFrameSorterGaps`), so that neither memory nor time grows
  # faster than the bytes.
  class CryptoStream
    FRAME_TYPE = 0x06
    MAX_RANGES = 1000

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
      # The bytes from `read_offset` to `received_end`, from `@window_start`
      # on in `@window`, and which of them have been received, as ranges in
      # order.
      @window = "".b
      @window_start = 0
      @filled = [] #: Array[Range[Integer]]
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
      return nil if Ranges.empty?(range)
      offset = range.begin
      length = [range.end - offset, room - 1 - Wire::Varint.size(offset) - Wire::Varint.size(room)].min
      return nil unless length.positive?
      if @lost.empty?
        @next_offset += length
      else
        rest = (offset + length)...range.end
        Ranges.empty?(rest) ? @lost.shift : @lost[0] = rest
      end
      data = @sent.byteslice(offset - @sent_base, length) #: String
      [Wire::Frame::Crypto.new(offset:, data:), Recovery::Duty::Crypto.new(space: @space, offset:, length:)]
    end

    # A range sent was acknowledged: it is not sent again, and the bytes up
    # to the first gap are let go.
    def acked(offset, length)
      @acked = Ranges.add(@acked, offset...(offset + length))
      @lost = Ranges.subtract(@lost, offset...(offset + length))
      first = @acked.first or return
      return unless first.begin <= @sent_base && first.end > @sent_base
      @sent = @sent.byteslice((first.end - @sent_base)..) #: String
      @sent_base = first.end
    end

    # A range sent was lost: what of it is not acknowledged goes again.
    def lost(offset, length)
      range = [offset, @sent_base].max...(offset + length)
      return if Ranges.empty?(range)
      @lost = @acked.reduce([range]) { |left, acked| Ranges.subtract(left, acked) }.reduce(@lost) { |lost, part| Ranges.add(lost, part) }
    end

    # Bytes received at `offset`, kept until read; a Violation of
    # CRYPTO_BUFFER_EXCEEDED when more than `limit` bytes would wait or the
    # bytes received would lie in more than MAX_RANGES pieces. A frame
    # without bytes changes nothing.
    def receive(offset, data, limit:)
      finish = offset + data.bytesize
      return if data.empty? || finish <= @read_offset
      exceeded("#{finish - @read_offset} CRYPTO bytes waiting, over #{limit}") if finish - @read_offset > limit
      if offset < @read_offset
        data = data.byteslice((@read_offset - offset)..) #: String
        offset = @read_offset
      end
      wanted = @window_start + finish - @read_offset
      @window << "\0".b * (wanted - @window.bytesize) if wanted > @window.bytesize
      @window.bytesplice(@window_start + offset - @read_offset, data.bytesize, data)
      fill(offset...finish)
      exceeded("CRYPTO bytes received in over #{MAX_RANGES} pieces") if @filled.size > MAX_RANGES
      @received_end = finish if finish > @received_end
    end

    # The first `length` bytes were received and read elsewhere: frames
    # carrying them again are old.
    def consumed(length)
      raise ArgumentError, "bytes have been received already" unless @received_end.zero?
      @received_end = @read_offset = length
    end

    # The bytes received from where reading stopped up to the first gap.
    # What is read stays at the front of the window until it is over half
    # of it, so that a frame received after a read does not copy the window
    # it would share with the bytes read.
    def read
      first = @filled.first
      return "".b unless first && first.begin == @read_offset
      length = first.end - @read_offset
      out = @window.byteslice(@window_start, length) #: String
      @window_start += length
      @read_offset = first.end
      @filled.shift
      if @window_start * 2 > @window.bytesize
        @window = @window.byteslice(@window_start..) #: String
        @window_start = 0
      end
      out
    end

    # How many bytes wait to be read, counted to the end of the furthest
    # frame.
    def buffered = @received_end - @read_offset

    private def send_end = @sent_base + @sent.bytesize

    private def exceeded(message) = raise Violation.new(message, code: ErrorCode::CRYPTO_BUFFER_EXCEEDED, frame_type: FRAME_TYPE)

    # `range` marked received, merged with the ranges it overlaps or
    # touches, found by binary search.
    private def fill(range)
      first = @filled.bsearch_index { |filled| filled.end >= range.begin } || @filled.size
      last = first
      start = range.begin
      finish = range.end
      while (filled = @filled[last]) && filled.begin <= finish
        start = filled.begin if filled.begin < start
        finish = filled.end if filled.end > finish
        last += 1
      end
      @filled[first...last] = [start...finish]
    end
  end
end
