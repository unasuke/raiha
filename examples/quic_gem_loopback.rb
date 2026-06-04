# Demonstrates a QUIC + TLS 1.3 handshake between the quic gem
# (github: unasuke/quic-ruby, a thin ngtcp2 + LibreSSL binding) acting as the
# client and Raiha::Server acting as the server, over loopback UDP.
#
# Why a subprocess rather than a Thread: the quic gem links a vendored LibreSSL,
# and loading it in the same process as Ruby's openssl (which raiha needs)
# crashes the interpreter. So raiha runs here while the quic gem client runs in
# a separate process via test/support/quic_gem_echo_client.rb.
#
# Scope note: this demo covers the handshake, which interoperates. It does not
# do a server->client echo round trip, because the quic gem client cannot yet
# read server-initiated stream data (see test/interop/quic/quic_gem_test.rb).
#
# The quic gem lives in the optional :interop bundle group. Run with:
#   bundle install --with interop
#   bundle exec ruby -Ilib examples/quic_gem_loopback.rb
#
# Expected output:
#   Raiha::Server accepted quic gem (ngtcp2) client, handshake OK

require "raiha/server"
require "securerandom"
require "socket"
require "timeout"
require_relative "_certificate"

ALPN = "raiha-interop"
ECHO_CLIENT = File.expand_path("../test/support/quic_gem_echo_client.rb", __dir__)

def find_available_udp_port
  socket = UDPSocket.new
  socket.bind("127.0.0.1", 0)
  port = socket.addr[1]
  socket.close
  port
end

server_port = find_available_udp_port

server_socket = UDPSocket.new
server_socket.bind("127.0.0.1", server_port)

server = Raiha::Server.new(tls_config: ExampleCertificate.tls_config, alpn_protocols: [ALPN])

# Drive the quic gem client (ngtcp2) in a separate process; it completes the
# handshake, prints HANDSHAKE_COMPLETE, and exits.
client_rd, client_wr = IO.pipe
client_pid = Process.spawn(
  "bundle", "exec", "ruby", ECHO_CLIENT,
  "--host", "127.0.0.1",
  "--port", server_port.to_s,
  "--alpn", ALPN,
  out: client_wr, err: client_wr
)
client_wr.close

server_conn = nil

begin
  Timeout.timeout(15) do
    loop do
      readable = IO.select([server_socket], nil, nil, 0.1)
      if readable
        begin
          data, addr = server_socket.recvfrom_nonblock(65535)
          response = server.handle_packet(data, addr)
          server_socket.send(response, 0, addr[3], addr[1]) if response
        rescue IO::WaitReadable
          # spurious wakeup; fall through to flush below
        end
      end

      server_conn ||= server.accept_nonblock
      if server_conn&.peer_address
        server_conn.get_packets_to_send.each do |packet|
          server_socket.send(packet, 0, server_conn.peer_address[3], server_conn.peer_address[1])
        end
      end

      break if server_conn&.handshake_complete?
    end
  end

  Process.wait(client_pid)
  client_output = client_rd.read
  unless server_conn&.handshake_complete? && client_output.include?("HANDSHAKE_COMPLETE")
    raise "handshake did not complete (client output: #{client_output.inspect})"
  end

  puts "Raiha::Server accepted quic gem (ngtcp2) client, handshake OK"
ensure
  Process.kill("TERM", client_pid) if client_pid rescue nil
  Process.wait(client_pid) if client_pid rescue nil
  server_socket.close
end
