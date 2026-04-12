# frozen_string_literal: true

module Raiha::Quic
  module Protocol
    module Perspective
      CLIENT = :client
      SERVER = :server

      def self.opposite(perspective)
        case perspective
        when CLIENT then SERVER
        when SERVER then CLIENT
        else raise ArgumentError, "Invalid perspective: #{perspective}"
        end
      end

      def self.client?(perspective)
        perspective == CLIENT
      end

      def self.server?(perspective)
        perspective == SERVER
      end
    end
  end
end
