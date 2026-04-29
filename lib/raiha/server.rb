# frozen_string_literal: true

require "socket"
require_relative "connection"
require_relative "config"
require_relative "quic/demuxer"
require_relative "quic/protocol"
require_relative "quic/wire/buffer"
require_relative "quic/wire/long_header"

module Raiha
  class Server
    attr_reader :connections

    def initialize(config: nil, stateless_reset_key: nil, retry_key: nil, require_retry: false, server_connection_id_length: 8)
      @config = config || Config.server_default
      @socket = nil
      @connections = {} #: Hash[String, Connection]
      @incoming_connections = Queue.new
      @closed = false
      @demuxer = Quic::Demuxer.new(
        stateless_reset_key: stateless_reset_key,
        retry_key: retry_key,
        require_retry: require_retry,
        server_connection_id_length: server_connection_id_length
      )
      @server_connection_id_length = server_connection_id_length
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

    # Process an incoming UDP datagram. Returns either a String of
    # response bytes the caller must send back to `addr` (Version
    # Negotiation, Retry, or Stateless Reset; produced by the
    # Demuxer) or nil when the datagram has been routed to a
    # Connection (existing or freshly created).
    def handle_packet(data, addr)
      response = @demuxer.dispatch(data, peer_address: addr)
      return response if response

      # Demuxer either delivered to a registered Connection, dropped
      # silently, or recognized a validated retry-token Initial. In
      # the last case we still need to materialize a Connection for
      # the application; see RFC 9000 §17.2.5.2 for the ODCID
      # plumbing.
      if (header = parse_long_header(data)) && header.initial?
        dcid = header.destination_connection_id.serialize
        return nil if @connections.key?(dcid)

        retry_validated_odcid = @demuxer.validated_original_dcid(dcid)
        connection = create_connection(header, retry_validated_odcid: retry_validated_odcid)
        @connections[connection.src_connection_id.serialize] = connection
        @demuxer.register(connection.src_connection_id, connection)
        @incoming_connections << connection
        connection.handle_packet(data, peer_address: addr)
      end
      nil
    end

    private def parse_long_header(data)
      return nil if data.bytesize < 1
      first_byte = data.getbyte(0)
      return nil unless first_byte && (first_byte & 0x80) != 0

      Quic::Wire::LongHeader.parse(Quic::Wire::Buffer.new(data))
    rescue StandardError
      nil
    end

    private def create_connection(header, retry_validated_odcid:)
      # Without Retry, the client's first Initial DCID is the ODCID
      # the client invented; the server picks its own CID. With
      # Retry, the client's second Initial DCID is the SCID we put
      # into the Retry, and the Connection should adopt that so
      # routing for follow-up packets stays stable.
      src_connection_id = if retry_validated_odcid
                            header.destination_connection_id
                          else
                            Quic::Protocol::ConnectionID.generate(length: @server_connection_id_length)
                          end
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
