# Demonstrates Connection#enable_qlog: completes the TLS 1.3 / QUIC
# handshake plus a STREAM echo (as in stream_echo.rb) with qlog recording
# turned on for both endpoints, and flushes the contained-schema qlog
# JSON to tmp/.
#
# Usage:
#   bundle exec ruby -Ilib examples/qlog_output.rb
#
# Expected output:
#   qlog written: tmp/raiha-example-qlog-client.qlog
#   qlog written: tmp/raiha-example-qlog-server.qlog

require "raiha/connection"
require "securerandom"
require "socket"
require "timeout"
require_relative "_certificate"

CLIENT_QLOG_PATH = "tmp/raiha-example-qlog-client.qlog"
SERVER_QLOG_PATH = "tmp/raiha-example-qlog-server.qlog"

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

client.enable_qlog(output: CLIENT_QLOG_PATH, title: "raiha example client")
server.enable_qlog(output: SERVER_QLOG_PATH, title: "raiha example server")

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

    # Drive timer-based work once on each side. No timer is typically due
    # right after a clean handshake, but exercising the API ensures the
    # qlog captures any deadline-driven events that do fire.
    client.next_timer_deadline
    client.tick(now: Time.now)
    server.next_timer_deadline
    server.tick(now: Time.now)

    client.send_stream_data(0, payload, fin: true)
    send_packets(client, client_socket, "127.0.0.1", server_port)
    receive_packets(server_socket, server)

    server_stream = server.streams.get_stream(0)
    raise "Server stream 0 not opened" unless server_stream
    received = server_stream.read

    server.send_stream_data(1, received, fin: true)
    send_packets(server, server_socket, "127.0.0.1", client_port)
    receive_packets(client_socket, client)

    client_stream = client.streams.get_stream(1)
    raise "Client stream 1 not opened" unless client_stream
    echoed = client_stream.read

    raise "Echo payload mismatch" unless echoed == payload
  end

  client.close
  send_packets(client, client_socket, "127.0.0.1", server_port)
  receive_packets(server_socket, server)

  client.flush_qlog
  server.flush_qlog

  puts "qlog written: #{CLIENT_QLOG_PATH}"
  puts "qlog written: #{SERVER_QLOG_PATH}"
ensure
  client_socket.close
  server_socket.close
end
