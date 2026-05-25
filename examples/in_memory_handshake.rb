# Demonstrates the minimal TLS 1.3 / QUIC handshake using two
# Raiha::Connection instances exchanging packets in-process (no socket).
#
# Usage:
#   bundle exec ruby -Ilib examples/in_memory_handshake.rb
#
# Expected output:
#   Handshake complete (client: true, server: true)

require "raiha/connection"
require_relative "_certificate"

dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate
src_connection_id = Raiha::Quic::Protocol::ConnectionID.generate

client = Raiha::Connection.new(
  perspective: :client,
  src_connection_id: src_connection_id,
  dest_connection_id: dest_connection_id,
  server_name: "localhost"
)

server = Raiha::Connection.new(
  perspective: :server,
  src_connection_id: dest_connection_id,
  dest_connection_id: dest_connection_id,
  tls_config: ExampleCertificate.tls_config
)

# 1-RTT handshake in three flights:
#   1. client Initial (ClientHello)
#   2. server Initial (ServerHello) + Handshake (EE+Cert+CV+Fin)
#   3. client Handshake (Finished)
client.start_handshake
client.get_packets_to_send.each { |packet| server.handle_packet(packet) }
server.get_packets_to_send.each { |packet| client.handle_packet(packet) }
client.get_packets_to_send.each { |packet| server.handle_packet(packet) }

client_done = client.handshake_complete?
server_done = server.handshake_complete?
raise "Handshake did not complete (client: #{client_done}, server: #{server_done})" unless client_done && server_done

puts "Handshake complete (client: #{client_done}, server: #{server_done})"

# Drain a CONNECTION_CLOSE from the client so the server enters draining.
client.close
client.get_packets_to_send.each { |packet| server.handle_packet(packet) }
