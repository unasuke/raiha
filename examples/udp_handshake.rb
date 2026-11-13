# A QUIC handshake over UDP on the loopback interface, with the loop an
# application writes around a connection: send what there is to send, take
# the events, then wait for a datagram or the next timeout, whichever comes
# first. A server's Endpoint runs the same loop in a thread of its own,
# taking every client.
#
# Usage:
#   bundle exec ruby -Ilib examples/udp_handshake.rb
#
# Expected output:
#   Connected to localhost with hq-interop
#   Handshake complete over UDP (client: true, server: true)

require "raiha/quic"
require "socket"
require_relative "_certificate"

QUIC = Raiha::Next::QUIC
TLS = Raiha::Next::TLS
REGISTRY = TLS::Extension::Registry::BUILTIN.with(QUIC::TransportParameters::Extension)
ALPN = ["hq-interop"].freeze

def mono = Process.clock_gettime(Process::CLOCK_MONOTONIC)

def handle(ev)
  puts "Connected to #{ev.handshake.server_name} with #{ev.handshake.alpn}" if ev.is_a?(QUIC::Event::Connected)
end

server_tls = TLS::Config.server(profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY)
server_keyring = TLS::Keyring.server(config: server_tls, identities: [ExampleCertificate.identity])
server_socket = UDPSocket.new
server_socket.bind("127.0.0.1", 0)
endpoint = QUIC::Endpoint.server(config: QUIC::Config.new, random: SecureRandom, time: Time.now, now: mono)
accepted = Thread::Queue.new
Thread.new do
  loop do
    endpoint.each_transmit(now: mono) { |t| server_socket.send(t.payload, 0, *t.destination) }

    deadline = endpoint.next_timeout
    timeout  = deadline ? [deadline - mono, 0].max : Float::INFINITY
    if IO.select([server_socket], nil, nil, timeout)
      data, addr = server_socket.recvfrom(65535)
      route = endpoint.receive(data, from: [addr[3], addr[1]], now: mono)
      route = endpoint.admit(route.handle, now: mono) if route.is_a?(QUIC::Route::Incoming)
      accepted << endpoint.accept(route.handle, tls_config: server_tls, keyring: server_keyring, now: mono) if route.is_a?(QUIC::Route::ClientHello)
      server_socket.send(route.transmit.payload, 0, *route.transmit.destination) if route.is_a?(QUIC::Route::Respond)
    else
      endpoint.handle_timeout(now: mono)
    end
  end
end

client_tls = TLS::Config.client(trust_anchors: [ExampleCertificate.ca_der], profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY)
socket = UDPSocket.new
socket.bind("127.0.0.1", 0)
conn = QUIC::Connection.client(config: QUIC::Config.new, tls_config: client_tls, keyring: TLS::Keyring.client(config: client_tls),
  server_name: "localhost", remote: ["127.0.0.1", server_socket.addr[1]], time: Time.now, now: mono)

until conn.handshake_confirmed? || conn.closed?
  conn.each_transmit(now: mono) { |t| socket.send(t.payload, 0, *t.destination) }
  conn.each_event { |ev| handle(ev) }

  deadline = conn.next_timeout
  timeout  = deadline ? [deadline - mono, 0].max : Float::INFINITY
  if IO.select([socket], nil, nil, timeout)
    data, addr = socket.recvfrom(65535)
    conn.receive(data, from: [addr[3], addr[1]], now: mono)
  else
    conn.handle_timeout(now: mono)
  end
end
abort "Handshake failed: #{conn.close_reason&.reason}" if conn.closed?

conn.close(now: mono)
conn.each_transmit(now: mono) { |t| socket.send(t.payload, 0, *t.destination) }
puts "Handshake complete over UDP (client: #{conn.handshake_complete?}, server: #{accepted.pop.handshake_complete?})"
