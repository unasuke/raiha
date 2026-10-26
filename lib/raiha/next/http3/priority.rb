# frozen_string_literal: true

require_relative "structured_field"

module Raiha::Next::HTTP3
  # The priority of a response (RFC 9218 "Priority Parameters"): its
  # urgency, from 0, the most urgent, to 7, and whether it is incremental.
  class Priority < Data.define(:urgency, :incremental)
    DEFAULT_URGENCY = 3
    URGENCIES = 0..7

    def initialize(urgency: DEFAULT_URGENCY, incremental: false)
      raise ArgumentError, "urgency is 0 to 7, not #{urgency.inspect}" unless urgency.is_a?(Integer) && URGENCIES.cover?(urgency)
      raise ArgumentError, "incremental is true or false, not #{incremental.inspect}" unless incremental == true || incremental == false
      super
    end

    # The urgency and the incremental a Priority Field Value gives, each nil
    # where it gives none, or one out of range or of another type, which
    # is ignored; nil for both when the value is not a Dictionary.
    def self.parameters(text)
      members = StructuredField.dictionary(text) or return nil
      urgency = members["u"]
      incremental = members["i"]
      [
        urgency.is_a?(Integer) && URGENCIES.cover?(urgency) ? urgency : nil,
        incremental == true || incremental == false ? incremental : nil
      ] #: [Integer?, bool?]
    end

    # The priority a request with the Priority header field `text`, or a
    # PRIORITY_UPDATE with it, asks for: the defaults where it gives none,
    # and all of them when it is no Dictionary.
    def self.parse(text)
      urgency, incremental = parameters(text)
      new(urgency: urgency || DEFAULT_URGENCY, incremental: incremental.nil? ? false : incremental)
    end

    # This one, with what `urgency` and `incremental` give in place of its
    # own; nil leaves one as it is, as a Priority in a response does
    # (RFC 9218 "Merging Client- and Server-Driven Priority Parameters").
    def merge(urgency, incremental) = with(urgency: urgency || self.urgency, incremental: incremental.nil? ? self.incremental : incremental)

    # The Priority Field Value that gives this one, empty for the defaults.
    def to_field
      parameters = [] #: Array[String]
      parameters << "u=#{urgency}" unless urgency == DEFAULT_URGENCY
      parameters << "i" if incremental
      parameters.join(", ")
    end
  end
end
