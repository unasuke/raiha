# frozen_string_literal: true

require_relative "context"

module Raiha
  module TLS
    class Client < Context
    # include Raiha::Buffer::Packable

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
        @supported_groups = []
        @transcript_hash = {}
      end

      def datagrams_to_send
        case @state
        when State::START
          @buffer << build_client_hello
          transition_state(State::WAIT_SH)
        end

        @buffer
      end

      def receive(datagram)
        case @state
        when State::WAIT_SH
          receive_server_hello(datagram)
        else
          # TODO: WIP
        end
      end

      def receive_server_hello(datagram)
        hs = Handshake.deserialize(datagram)
        if hs.handshake_type == Handshake::HANDSHAKE_TYPE[:server_hello]

        else
          # TODO: alert?
        end
      end

      def build_client_hello
        hs_clienthello = Handshake.new.tap do |hs|
          hs.handshake_type = Handshake::HANDSHAKE_TYPE[:client_hello]
          hs.message = ClientHello.build
        end
        @transcript_hash[:client_hello] = hs_clienthello
        # hs_clienthello.serialize
        Record.serialize(hs_clienthello)
      end

      private def transition_state(state)
        if @state == State::START && state == State::WAIT_SH
          @state = state
        end
      end
    end
  end
end
