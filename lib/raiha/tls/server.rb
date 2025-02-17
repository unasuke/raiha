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
        @cipher_suite = nil
        @client_hello = nil
        @server_hello = nil
        @buffer = []
        @received = []
      end

      def receive(datagram)
        @received = Record.deserialize(datagram)

        case @state
        when State::START
          receive_client_hello
        end
      end

      def receive_client_hello(datagrams)
        # binding.irb
        records = Raiha::TLS::Record::TLSPlaintext.deserialize(datagrams)
        hs = records.first
        if hs.handshake_type != Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
          raise "TODO: alert? not client hello"
        end

        @client_hello = hs.message
      end

      def receive_client_hello
        loop do
          received = @received.shift
          break if received.nil?

          if received.plaintext? && received.handshake? && received.fragment.message.is_a?(Handshake::ClientHello)
            @client_hello = received.fragment.message
            break
          else
            # TODO: not a client hello
          end
        end

        unless @cipher_suite = choose_cipher_suite(@client_hello.cipher_suites)
          raise "TODO: alert? cannot choose cipher suite"
        end

        transition_state(State::RECVD_CH)
      end

      def choose_cipher_suite(cipher_suites)
        cipher_suites.find(&:supported?)
      end

      private def transition_state(state)
        if @state == State::START && state == State::RECVD_CH
          @state = state
        end
      end
    end
  end
end
