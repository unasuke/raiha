# Demonstrates a TLS 1.3 / QUIC handshake between two Raiha::Connection
# instances over real UDP sockets on the loopback interface.
#
# Usage:
#   bundle exec ruby -Ilib examples/udp_handshake.rb
#
# Expected output:
#   Handshake complete over UDP (client: true, server: true)

require "raiha/connection"
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

begin
  Timeout.timeout(5) do
    client.start_handshake
    send_packets(client, client_socket, "127.0.0.1", server_port)
    receive_packets(server_socket, server)

    send_packets(server, server_socket, "127.0.0.1", client_port)
    receive_packets(client_socket, client)

    send_packets(client, client_socket, "127.0.0.1", server_port)
    receive_packets(server_socket, server)
  end

  client_done = client.handshake_complete?
  server_done = server.handshake_complete?
  raise "Handshake did not complete (client: #{client_done}, server: #{server_done})" unless client_done && server_done

  puts "Handshake complete over UDP (client: #{client_done}, server: #{server_done})"

  client.close
  send_packets(client, client_socket, "127.0.0.1", server_port)
  receive_packets(server_socket, server)
ensure
  client_socket.close
  server_socket.close
end
