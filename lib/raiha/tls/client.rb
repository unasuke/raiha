# frozen_string_literal: true

require_relative "context"
require_relative "record"
require_relative "handshake"

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

      attr_reader :state

      def initialize
        @state = State::START
        @buffer = []
        @supported_groups = []
        @transcript_hash = {}
      end

      def datagrams_to_send
        case @state
        when State::START
          build_client_hello.tap do
            transition_state(State::WAIT_SH)
          end
        end

        @buffer
      end

      def receive(datagrams)
        case @state
        when State::WAIT_SH
          receive_server_hello(datagrams)
        else
          # TODO: WIP
        end
      end

      def receive_server_hello(datagrams)
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
        elsif @state == State::WAIT_SH && state == State::WAIT_EE
          @state = state
        elsif @state == State::WAIT_EE && state == State::WAIT_CERT_CR
          @state = state
        elsif @state == State::WAIT_CERT_CR && state == State::WAIT_CV
          @state = state
        elsif @state == State::WAIT_CV && state == State::WAIT_FINISHED
          @state = state
        else
          raise "TODO: #{@state} -> #{state} is wrong state transition"
        end
      end
    end
  end
end
