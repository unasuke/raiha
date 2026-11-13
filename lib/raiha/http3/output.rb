# frozen_string_literal: true

module Raiha::HTTP3
  # What waits to go on one stream: the bytes of its frames in order, and
  # whether the stream ends after them. Given to the transport a piece at
  # a time; when it takes less than a piece, the rest waits, and so does
  # the stream, until the transport can take more.
  class Output
    # The bytes waiting.
    attr_reader :buffered

    def initialize
      @pieces = [] #: Array[String]
      @buffered = 0
      @fin = false
      @blocked = false
    end

    def <<(bytes)
      raise Error::Usage, "the stream has ended" if @fin
      @pieces << bytes unless bytes.empty?
      @buffered += bytes.bytesize
      self
    end

    # The stream ends after what waits.
    def finish
      @fin = true
    end

    # Whether the transport is to be given something now.
    def ready? = !@blocked && (!@pieces.empty? || @fin)

    # The transport can take more again.
    def unblock
      @blocked = false
    end

    # Gives the waiting pieces to the block, the last with the end of the
    # stream if it ends, until the block, which returns how many bytes it
    # took, takes less than a piece. Whether all went, the end with them.
    def drain
      until @blocked
        piece = @pieces.first || ""
        fin = @fin && @pieces.size <= 1
        return false if piece.empty? && !fin
        taken = yield(piece, fin)
        raise ArgumentError, "#{taken.inspect} bytes taken of #{piece.bytesize}" unless taken.is_a?(Integer) && taken.between?(0, piece.bytesize)
        @buffered -= taken
        if taken < piece.bytesize
          @pieces[0] = piece.byteslice(taken..) # steep:ignore
          @blocked = true
          return false
        end
        @pieces.shift
        return true if fin
      end
      false
    end
  end
end
