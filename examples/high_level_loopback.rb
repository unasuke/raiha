# Demonstrates the Raiha::Server demuxer / accept flow. Drives the server
# side through `Raiha::Server.new(tls_config: ...)` + `handle_packet` +
# `accept_nonblock` instead of low-level Connection wiring, but binds the
# UDPSocket externally because Server#listen hides the socket behind a
# private ivar. The client side stays on Raiha::Connection directly for
# the same reason.
#
# Usage:
#   bundle exec ruby -Ilib examples/high_level_loopback.rb
#
# Expected output:
#   Raiha::Server accepted 1 connection, stream echo OK

require "raiha/server"
require "raiha/connection"
require "securerandom"
require "socket"
require "timeout"
require_relative "_certificate"

def find_available_udp_port
  socket = UDPSocket.new
  socket.bind("127.0.0.1", 0)
  port = socket.addr[1]
  socket.close
  port
end

# Receive any pending datagrams on the server socket, dispatch them
# through Raiha::Server#handle_packet, and bounce back any
# demuxer-produced response (Version Negotiation, Stateless Reset, etc.).
def drain_server(server, server_socket)
  loop do
    readable = IO.select([server_socket], nil, nil, 0.1)
    break unless readable

    data, addr = server_socket.recvfrom_nonblock(65535)
    response = server.handle_packet(data, addr)
    server_socket.send(response, 0, addr[2], addr[1]) if response
  rescue IO::WaitReadable
    break
  end
end

# Pull every queued outgoing packet from every Server-owned Connection and
# write it back to the address we recorded for that Connection via
# `handle_packet(peer_address:)`.
def flush_server(server, server_socket)
  server.connections.each_value do |conn|
    next unless conn.peer_address

    conn.get_packets_to_send.each do |packet|
      server_socket.send(packet, 0, conn.peer_address[2], conn.peer_address[1])
    end
  end
end

def send_client(client, client_socket, host, port)
  client.get_packets_to_send.each { |packet| client_socket.send(packet, 0, host, port) }
end

def receive_client(client_socket, client)
  loop do
    readable = IO.select([client_socket], nil, nil, 0.1)
    break unless readable

    data, = client_socket.recvfrom_nonblock(65535)
    client.handle_packet(data)
  rescue IO::WaitReadable
    break
  end
end

client_port = find_available_udp_port
server_port = find_available_udp_port

client_socket = UDPSocket.new
client_socket.bind("127.0.0.1", client_port)

server_socket = UDPSocket.new
server_socket.bind("127.0.0.1", server_port)

server = Raiha::Server.new(tls_config: ExampleCertificate.tls_config)

client = Raiha::Connection.new(
  perspective: :client,
  src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
  dest_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
  server_name: "localhost"
)

payload = SecureRandom.random_bytes(256)
server_conn = nil

begin
  Timeout.timeout(5) do
    client.start_handshake
    send_client(client, client_socket, "127.0.0.1", server_port)

    drain_server(server, server_socket)
    server_conn = server.accept_nonblock
    raise "Raiha::Server did not accept a Connection" unless server_conn
    flush_server(server, server_socket)

    receive_client(client_socket, client)
    send_client(client, client_socket, "127.0.0.1", server_port)

    drain_server(server, server_socket)
    flush_server(server, server_socket)
    receive_client(client_socket, client)

    unless client.handshake_complete? && server_conn.handshake_complete?
      raise "Handshake did not complete (client: #{client.handshake_complete?}, server: #{server_conn.handshake_complete?})"
    end

    client.send_stream_data(0, payload, fin: true)
    send_client(client, client_socket, "127.0.0.1", server_port)
    drain_server(server, server_socket)

    server_stream = server_conn.streams.get_stream(0)
    raise "Server stream 0 not opened" unless server_stream
    received = server_stream.read

    server_conn.send_stream_data(1, received, fin: true)
    flush_server(server, server_socket)
    receive_client(client_socket, client)

    client_stream = client.streams.get_stream(1)
    raise "Client stream 1 not opened" unless client_stream
    echoed = client_stream.read

    raise "Echo payload mismatch" unless echoed == payload
  end

  puts "Raiha::Server accepted 1 connection, stream echo OK"

  client.close
  send_client(client, client_socket, "127.0.0.1", server_port)
  drain_server(server, server_socket)
ensure
  client_socket.close
  server_socket.close
end
