# frozen_string_literal: true

module Raiha::Next::QUIC
  # The packets a connection cannot open yet, as their keys have not come
  # (RFC 9001 "Receiving Out-of-Order Protected Packets"): no more than
  # PACKETS of them, nor BYTES in all, so that what a peer can make a
  # connection keep is bounded. Each is kept as a String of its own, never
  # as a part of the datagram it came in, which a substring to its end
  # would keep whole.
  class KeptPackets
    PACKETS = 10
    BYTES = 16 * 1024

    # A packet kept: its bytes and level, the addresses and ECN codepoint
    # of its datagram, and when it came.
    Kept = Data.define(:bytes, :level, :from, :to, :ecn, :received_at)

    def initialize
      @kept = [] #: Array[Kept]
      @bytes = 0
    end

    def empty? = @kept.empty?

    # Keeps the packet `bytes` of `level`: whether there was room for it.
    def keep(bytes, level:, from:, to:, ecn:, received_at:)
      return false if @kept.size >= PACKETS || @bytes + bytes.bytesize > BYTES
      @kept << Kept.new(bytes: "".b << bytes, level:, from:, to:, ecn:, received_at:)
      @bytes += bytes.bytesize
      true
    end

    # Takes out the packets whose level the block is true of, in the order
    # they came.
    def take
      taken, @kept = @kept.partition { |kept| yield kept.level }
      @bytes -= taken.sum { |kept| kept.bytes.bytesize }
      taken
    end
  end
end
