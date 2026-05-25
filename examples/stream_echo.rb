# Demonstrates a full bidirectional STREAM exchange after the TLS 1.3 /
# QUIC handshake: client sends 256 random bytes on stream 0, server reads
# them and echoes the same bytes back on stream 1, client verifies.
#
# Usage:
#   bundle exec ruby -Ilib examples/stream_echo.rb
#
# Expected output:
#   Echo matched: 256 bytes

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

def send_packets(connection, socket, host, port)
  connection.get_packets_to_send.each { |packet| socket.send(packet, 0, host, port) }
end

def receive_packets(socket, connection)
  loop do
    readable = IO.select([socket], nil, nil, 0.1)
    break unless readable

    data, = socket.recvfrom_nonblock(65535)
    connection.handle_packet(data)
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

dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate

client = Raiha::Connection.new(
  perspective: :client,
  src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
  dest_connection_id: dest_connection_id,
  server_name: "localhost"
)

server = Raiha::Connection.new(
  perspective: :server,
  src_connection_id: dest_connection_id,
  dest_connection_id: dest_connection_id,
  tls_config: ExampleCertificate.tls_config
)

payload = SecureRandom.random_bytes(256)

begin
  Timeout.timeout(5) do
    client.start_handshake
    send_packets(client, client_socket, "127.0.0.1", server_port)
    receive_packets(server_socket, server)

    send_packets(server, server_socket, "127.0.0.1", client_port)
    receive_packets(client_socket, client)

    send_packets(client, client_socket, "127.0.0.1", server_port)
    receive_packets(server_socket, server)

    raise "Handshake did not complete" unless client.handshake_complete? && server.handshake_complete?

    # client (stream 0) → server
    client.send_stream_data(0, payload, fin: true)
    send_packets(client, client_socket, "127.0.0.1", server_port)
    receive_packets(server_socket, server)

    server_stream = server.streams.get_stream(0)
    raise "Server stream 0 not opened" unless server_stream
    raise "Server stream 0 has no data" unless server_stream.data_available?
    received_by_server = server_stream.read

    # server (stream 1) → client
    server.send_stream_data(1, received_by_server, fin: true)
    send_packets(server, server_socket, "127.0.0.1", client_port)
    receive_packets(client_socket, client)

    client_stream = client.streams.get_stream(1)
    raise "Client stream 1 not opened" unless client_stream
    raise "Client stream 1 has no data" unless client_stream.data_available?
    echoed = client_stream.read

    raise "Echo payload mismatch" unless echoed == payload
  end

  puts "Echo matched: #{payload.bytesize} bytes"

  client.close
  send_packets(client, client_socket, "127.0.0.1", server_port)
  receive_packets(server_socket, server)
ensure
  client_socket.close
  server_socket.close
end
