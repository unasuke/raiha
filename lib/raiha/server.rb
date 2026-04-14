# frozen_string_literal: true

require "socket"
require_relative "connection"
require_relative "config"
require_relative "quic/protocol"
require_relative "quic/wire/buffer"
require_relative "quic/wire/long_header"

module Raiha
  class Server
    attr_reader :connections

    def initialize(config: nil)
      @config = config || Config.server_default
      @socket = nil
      @connections = {}
      @incoming_connections = Queue.new
      @closed = false
    end

    def listen(host, port)
      @socket = UDPSocket.new
      @socket.bind(host, port)
      self
    end

    def accept
      @incoming_connections.pop
    end

    def accept_nonblock
      @incoming_connections.pop(true)
    rescue ThreadError
      nil
    end

    def close
      return if @closed

      @closed = true
      @connections.each_value do |connection|
        connection.close(error_code: 0, reason: "Server shutdown")
      end
      @socket&.close
    end

    def handle_packet(data, addr)
      buffer = Quic::Wire::Buffer.new(data)
      first_byte = buffer.read_uint8
      buffer.seek(0)

      if (first_byte & 0x80) != 0
        header = Quic::Wire::LongHeader.parse(buffer)
      else
        return
      end

      connection_id_key = header.destination_connection_id.to_s
      connection = @connections[connection_id_key]

      if connection.nil? && header.initial?
        connection = create_connection(header)
        @connections[connection_id_key] = connection
        @incoming_connections << connection
      end

      connection
    end

    private def create_connection(header)
      src_connection_id = Quic::Protocol::ConnectionID.generate
      dest_connection_id = header.source_connection_id

      Connection.new(
        perspective: Quic::Protocol::Perspective::SERVER,
        src_connection_id: src_connection_id,
        dest_connection_id: dest_connection_id,
        transport_parameters: @config.to_transport_parameters
      )
    end
  end
end
