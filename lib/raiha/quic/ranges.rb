# frozen_string_literal: true

module Raiha::QUIC
  # Sets of byte offsets as ranges that neither overlap nor touch, in
  # order: what of a stream has been acknowledged or must go again.
  module Ranges
    module_function

    def empty?(range) = range.begin >= range.end

    # `ranges` with `range` added, merged, in order.
    def add(ranges, range)
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
    def subtract(ranges, range)
      ranges.flat_map do |part|
        [part.begin...[part.end, range.begin].min, [part.begin, range.end].max...part.end].reject { |piece| empty?(piece) }
      end
    end
  end
end
