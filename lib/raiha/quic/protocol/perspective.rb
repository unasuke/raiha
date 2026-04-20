# frozen_string_literal: true

module Raiha::Quic
  module Protocol
    # Value object describing which end of a QUIC connection an endpoint
    # is playing. Exposes #client? / #server? / #opposite so callers can
    # branch on the role without comparing against module constants.
    #
    # Construct via the CLIENT and SERVER singletons; accept Symbol inputs
    # (e.g. `perspective: :client`) at API boundaries by passing through
    # .coerce.
    class Perspective
      CLIENT_VALUE = :client
      SERVER_VALUE = :server

      VALID_VALUES = [CLIENT_VALUE, SERVER_VALUE].freeze

      attr_reader :value

      def initialize(value)
        raise ArgumentError, "Invalid perspective: #{value.inspect}" unless VALID_VALUES.include?(value)

        @value = value
      end

      def client?
        @value == CLIENT_VALUE
      end

      def server?
        @value == SERVER_VALUE
      end

      def opposite
        client? ? SERVER : CLIENT
      end

      def ==(other)
        case other
        when Perspective then @value == other.value
        when Symbol then @value == other
        else false
        end
      end

      def to_s
        @value.to_s
      end

      def inspect
        "#<Perspective #{@value}>"
      end

      # Coerce either an existing Perspective instance or a :client / :server
      # Symbol into the canonical Perspective instance. Used at API
      # boundaries so internal code can assume @perspective is a Perspective.
      def self.coerce(input)
        case input
        when Perspective then input
        when CLIENT_VALUE then CLIENT
        when SERVER_VALUE then SERVER
        else raise ArgumentError, "Invalid perspective: #{input.inspect}"
        end
      end

      CLIENT = new(CLIENT_VALUE)
      SERVER = new(SERVER_VALUE)
    end
  end
end
