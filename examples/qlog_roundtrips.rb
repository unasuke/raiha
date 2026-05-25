# Generates a richer qlog trace by performing many STREAM echo roundtrips
# over a single TLS 1.3 / QUIC connection. After the handshake, the
# client opens a fresh bidirectional stream on each roundtrip (id 4*n)
# and sends a 512-byte random payload; the server reads it and echoes it
# back on the matching server-initiated stream (id 4*n+1). The resulting
# qlog files capture the handshake plus every per-round packet_sent /
# packet_received event, which is useful for visualization tools.
#
# Usage:
#   bundle exec ruby -Ilib examples/qlog_roundtrips.rb
#
# Expected output:
#   qlog written: tmp/raiha-example-qlog-roundtrips-client.qlog
#   qlog written: tmp/raiha-example-qlog-roundtrips-server.qlog
#   20 roundtrips OK (512 bytes each)

require "raiha/connection"
require "securerandom"
require "socket"
require "timeout"
require_relative "_certificate"

ROUNDTRIPS = 20
PAYLOAD_SIZE = 512
CLIENT_QLOG_PATH = "tmp/raiha-example-qlog-roundtrips-client.qlog"
SERVER_QLOG_PATH = "tmp/raiha-example-qlog-roundtrips-server.qlog"

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

client.enable_qlog(output: CLIENT_QLOG_PATH, title: "raiha example roundtrips client")
server.enable_qlog(output: SERVER_QLOG_PATH, title: "raiha example roundtrips server")

begin
  Timeout.timeout(20) do
    client.start_handshake
    send_packets(client, client_socket, "127.0.0.1", server_port)
    receive_packets(server_socket, server)

    send_packets(server, server_socket, "127.0.0.1", client_port)
    receive_packets(client_socket, client)

    send_packets(client, client_socket, "127.0.0.1", server_port)
    receive_packets(server_socket, server)

    raise "Handshake did not complete" unless client.handshake_complete? && server.handshake_complete?

    ROUNDTRIPS.times do |i|
      client_stream_id = 4 * i
      server_stream_id = 4 * i + 1
      payload = SecureRandom.random_bytes(PAYLOAD_SIZE)

      client.send_stream_data(client_stream_id, payload, fin: true)
      send_packets(client, client_socket, "127.0.0.1", server_port)
      receive_packets(server_socket, server)

      server_stream = server.streams.get_stream(client_stream_id)
      raise "Server stream #{client_stream_id} not opened" unless server_stream
      received = server_stream.read
      raise "Server payload mismatch on round #{i}" unless received == payload

      server.send_stream_data(server_stream_id, received, fin: true)
      send_packets(server, server_socket, "127.0.0.1", client_port)
      receive_packets(client_socket, client)

      client_stream = client.streams.get_stream(server_stream_id)
      raise "Client stream #{server_stream_id} not opened" unless client_stream
      echoed = client_stream.read
      raise "Client echo mismatch on round #{i}" unless echoed == payload
    end
  end

  client.close
  send_packets(client, client_socket, "127.0.0.1", server_port)
  receive_packets(server_socket, server)

  client.flush_qlog
  server.flush_qlog

  puts "qlog written: #{CLIENT_QLOG_PATH}"
  puts "qlog written: #{SERVER_QLOG_PATH}"
  puts "#{ROUNDTRIPS} roundtrips OK (#{PAYLOAD_SIZE} bytes each)"
ensure
  client_socket.close
  server_socket.close
end
