# frozen_string_literal: true

require_relative "error"

module Raiha::Next::HTTP3::QPACK
  # The dynamic table as the decoder keeps it (RFC 9204 "Dynamic Table"):
  # entries by absolute index, the oldest evicted first. The entries sit in
  # a ring, so inserting and evicting move none of the others; the ring
  # doubles when it fills, which the capacity bounds.
  #
  # The table is looked up by index only. The encoder, which would look up
  # names and values, inserts nothing yet.
  class DynamicTable
    # RFC 9204 "Dynamic Table Size": an entry's size is its name's and
    # value's octets and 32 more.
    ENTRY_OVERHEAD = 32
    INITIAL_SLOTS = 16

    # The capacity the encoder set, the size of the entries held, and how
    # many entries were ever inserted, which is the absolute index of the
    # next one.
    attr_reader :capacity, :size, :insert_count

    def initialize(max_capacity)
      @max_capacity = max_capacity
      @capacity = 0
      @size = 0
      @insert_count = 0
      # The absolute index of the oldest entry held.
      @evicted = 0
      @ring = Array.new(INITIAL_SLOTS) #: Array[[String, String]?]
    end

    # RFC 9204 "Required Insert Count": the most entries the table can
    # hold, by the maximum capacity rather than the one set.
    def max_entries = @max_capacity / ENTRY_OVERHEAD

    # Set Dynamic Table Capacity: evicts down to `capacity`, which may not
    # pass the maximum.
    def resize(capacity)
      raise Malformed, "a capacity of #{capacity} past the maximum of #{@max_capacity}" if capacity > @max_capacity
      @capacity = capacity
      evict_down_to(capacity)
    end

    # Inserts [name, value] after evicting what it needs room for. An entry
    # larger than the capacity raises Malformed. `name` and `value` are
    # frozen, so one taken from an entry the insertion evicts stays whole.
    def insert(name, value)
      entry_size = name.bytesize + value.bytesize + ENTRY_OVERHEAD
      raise Malformed, "an entry of #{entry_size} octets in a table of #{@capacity}" if entry_size > @capacity
      evict_down_to(@capacity - entry_size)
      grow if @insert_count - @evicted == @ring.size
      @ring[@insert_count & (@ring.size - 1)] = [name, value]
      @insert_count += 1
      @size += entry_size
    end

    # The entry at the absolute index `index`, or nil for one evicted or
    # yet to be inserted.
    def entry(index)
      return nil unless index >= @evicted && index < @insert_count
      @ring[index & (@ring.size - 1)]
    end

    private def evict_down_to(limit)
      while @size > limit
        slot = @evicted & (@ring.size - 1)
        name, value = @ring[slot] #: [String, String]
        @size -= name.bytesize + value.bytesize + ENTRY_OVERHEAD
        @ring[slot] = nil
        @evicted += 1
      end
    end

    # Doubles the ring, laying each entry at its absolute index anew.
    private def grow
      ring = Array.new(@ring.size * 2) #: Array[[String, String]?]
      (@evicted...@insert_count).each { |index| ring[index & (ring.size - 1)] = @ring[index & (@ring.size - 1)] }
      @ring = ring
    end
  end
end
