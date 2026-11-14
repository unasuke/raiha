# frozen_string_literal: true

module Raiha::HTTP3::QPACK
  # A field line. `never_indexed` is the N bit of RFC 9204 "Literal Field
  # Line with Name Reference": the line is always sent as a literal, here
  # and on every hop after. The Strings are frozen, copied first when the
  # caller's are not.
  class Field < Data.define(:name, :value, :never_indexed)
    def initialize(name:, value:, never_indexed: false)
      name = name.dup.freeze unless name.frozen?
      value = value.dup.freeze unless value.frozen?
      super
    end
  end
end
