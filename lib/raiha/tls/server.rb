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
          select_parameters
        end
      end

      def datagrams_to_send
        case @state
        when State::RECVD_CH
          [
            build_server_hello,
            build_encrypted_extensions,
            build_certificate,
            build_certificate_verify,
            build_finished,
          ]
        else
          # TODO: WIP
        end
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

      def select_parameters
        raise unless @client_hello
        # TODO: select parameters
      end

      def build_server_hello
      end

      def build_enctypted_extensions
      end

      def build_certificate
      end

      def build_certificate_verify
      end

      def build_finished
      end

      private def transition_state(state)
        if @state == State::START && state == State::RECVD_CH
          @state = state
        end
      end
    end
  end
end
