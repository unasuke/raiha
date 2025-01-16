# frozen_string_literal: true

require_relative "context"
require_relative "record"
require_relative "handshake"

module Raiha
  module TLS
    class Server < Context
      module State
        START = :START
        RECVD_CH = :RECVD_CH
        NEGOTIATED = :NEGOTIATED
        WAIT_EOED = :WAIT_EOED
        WAIT_FLIGHT2 = :WAIT_FLIGHT2
        WAIT_CERT = :WAIT_CERT
        WAIT_CV = :WAIT_CV
        WAIT_FINISHED = :WAIT_FINISHED
        CONNECTED = :CONNECTED
      end

      attr_reader :state

      def initialize
        @state = State::START
      end

      def receive()
      end

      def receive_client_hello()
      end

      private def transition_state(state)
        if @state == State::START && state == State::RECVD_CH
          @state = state
        end
      end
    end
  end
end
