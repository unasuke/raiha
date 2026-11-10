# frozen_string_literal: true

module Raiha::Next::QUIC
  # The search of a path for the largest datagram it carries (RFC 8899
  # "Datagram Packetization Layer Path MTU Discovery"), one probe at a
  # time: the largest it may carry first, then halfway between the largest
  # that got through and the smallest that did not. A size is given up on
  # once MAX_LOSSES of its probes in a row are lost; a probe that gets
  # through, late included, counts as through and starts the losses over.
  # The search is done once the largest gets through, or once what got
  # through and what did not are CLOSE_ENOUGH; it does not start again,
  # as RFC 8899's PMTU_RAISE_TIMER would.
  class MTUSearch
    # Bytes between what got through and what did not that end the search.
    CLOSE_ENOUGH = 20
    # Probes of a size lost in a row that give the size up.
    MAX_LOSSES = 3

    # From `from` bytes, which the path carries, up to `up_to`.
    def initialize(from:, up_to:)
      @through = from
      @failed = nil #: Integer?
      @max = up_to
      @probing = nil #: Integer?
      # The size whose probes were lost last, and how many in a row.
      @losing = nil #: Integer?
      @losses = 0
    end

    # The size of the next probe; nil while one is out, or once the search
    # is done.
    def next_size
      return nil if @probing || done?
      failed = @failed
      failed ? (@through + failed) / 2 : @max
    end

    def done?
      failed = @failed
      @through >= @max || (!failed.nil? && failed - @through <= CLOSE_ENOUGH)
    end

    # A probe of `size` went.
    def sent(size) = @probing = size

    # A probe of `size` got through: the size the path carries now, when
    # it is larger than before; else nil.
    def acked(size)
      @probing = nil if @probing == size
      @losses = 0
      return nil if size <= @through
      @through = size
      failed = @failed
      @failed = nil if failed && failed <= size
      size
    end

    # A probe of `size` was lost; one no larger than what got through
    # tells nothing.
    def lost(size)
      @probing = nil if @probing == size
      return if size <= @through
      @losses = @losing == size ? @losses + 1 : 1
      @losing = size
      return if @losses < MAX_LOSSES
      @losses = 0
      failed = @failed
      @failed = size if failed.nil? || size < failed
    end
  end
end
