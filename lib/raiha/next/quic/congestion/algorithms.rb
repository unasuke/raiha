# frozen_string_literal: true

module Raiha::Next::QUIC
  module Congestion
    # The algorithms that come with the layer, by name.
    ALGORITHMS = { new_reno: NewReno }.freeze

    # The algorithm `name` stands for: a Symbol of ALGORITHMS, or a class,
    # one of these or of the application's own, passed through as it is.
    def self.resolve(name)
      case name
      when Symbol then ALGORITHMS.fetch(name) { raise ArgumentError, "unknown congestion control: #{name.inspect}" }
      else name
      end
    end
  end
end
