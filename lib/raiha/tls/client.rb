# frozen_string_literal: true

module Raiha::TLS
  class Client < Context
    module State
      START = :START
      WAIT_SH = :WAIT_SH
      WAIT_EE = :WAIT_EE
      WAIT_CERT_CR = :WAIT_CERT_CR
      WAIT_CERT = :WAIT_CERT
      WAIT_CV = :WAIT_CV
      WAIT_FINISHED = :WAIT_FINISHED
      CONNECTED = :CONNECTED
    end

    def initialize
      @state = State::START
      @buffer = []
    end

    def datagrams_to_send
      case @state
      when State::START
        @buffer << send_client_hello
      end

      @buffer
    end

    def receive_datagram(datagram)
    end

    def send_client_hello
    end
  end
end
