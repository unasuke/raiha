# frozen_string_literal: true

require "socket"
require_relative "../raiha"
require_relative "connection"
require_relative "config"
require_relative "quic/protocol"

module Raiha
  class Client
    attr_reader :connection

    def initialize(config: nil)
      @config = config || Config.client_default
      @socket = nil
      @connection = nil
      @closed = false
    end

    def connect(host, port)
      raise Raiha::Error, "Already connected" if @connection

      @socket = UDPSocket.new
      @socket.connect(host, port)

      src_connection_id = Quic::Protocol::ConnectionID.generate
      dest_connection_id = Quic::Protocol::ConnectionID.generate

      @connection = Connection.new(
        perspective: Quic::Protocol::Perspective::CLIENT,
        src_connection_id: src_connection_id,
        dest_connection_id: dest_connection_id,
        transport_parameters: @config.to_transport_parameters
      )

      self
    end

    def open_stream(bidirectional: true)
      (@connection || raise(Raiha::Error, "Not connected")).open_stream(bidirectional: bidirectional)
    end

    def accept_stream
      (@connection || raise(Raiha::Error, "Not connected")).accept_stream
    end

    def close(error_code: 0, reason: "")
      return if @closed

      @closed = true
      @connection&.close(error_code: error_code, reason: reason)
      @socket&.close
    end

    def connected?
      @connection&.handshake_complete? && !@closed
    end
  end
end
