# frozen_string_literal: true

require_relative "context"

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

      def initialize
        @state = State::START
      end

      def receive()
      end

      def receive_client_hello()
      end
    end
  end
end
