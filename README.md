# Raiha

Raiha is QUIC, HTTP/3 and TLS 1.3 written in Ruby. The protocols are implemented in Ruby itself; the `openssl` gem provides only the cryptographic primitives.

- QUIC version 1 (RFC 9000, RFC 9001, RFC 9002): streams, DATAGRAM frames (RFC 9221), 0-RTT and resumption, Retry, connection migration and preferred addresses, path MTU discovery, ECN, NewReno and CUBIC
- HTTP/3 (RFC 9114) with QPACK (RFC 9204) and extensible priorities (RFC 9218)
- TLS 1.3, for QUIC and over TCP
- A sans-I/O core: the protocols do no I/O, and you drive them from your own socket loop
- A runtime that serves and connects over UDP sockets under a Fiber scheduler, with Ractor workers, a Rack 3 adapter and qlog, and one on threads that needs no scheduler

## Requirements

- Ruby 4.0 or later
- The `openssl` gem 4.0 or later, with OpenSSL or LibreSSL
- Linux or OpenBSD

## Installation

Add Raiha to your Gemfile:

```ruby
gem "raiha", github: "unasuke/raiha"
```

The runtime also needs a Fiber scheduler, such as the `async` gem; see [Fiber scheduler](docs/fiber-scheduler.md). The runtime on threads needs none; see [Threads](docs/threads.md).

## Usage

An HTTP/3 server that answers every request, blocking on its socket:

```ruby
require "raiha"
require "socket"

def now = Process.clock_gettime(Process::CLOCK_MONOTONIC)

chain = OpenSSL::X509::Certificate.load(File.read("cert.pem")).map(&:to_der)
key = OpenSSL::PKey.read(File.read("key.pem")).private_to_der
identity = Raiha::TLS::Keyring::Identity.new(cert_der: chain, key_der: key)

tls_config = Raiha::TLS::Config.server(
  profile: Raiha::TLS::Profile::QUIC,
  alpn: ["h3"],
  registry: Raiha::TLS::Extension::Registry::BUILTIN.with(Raiha::QUIC::TransportParameters::Extension)
)
keyring = Raiha::TLS::Keyring.server(config: tls_config, identities: [identity])

socket = UDPSocket.new
socket.bind("127.0.0.1", 4433)
endpoint = Raiha::QUIC::Endpoint.server(config: Raiha::QUIC::Config.new(ecn_address_families: [], enable_pmtud: false), random: SecureRandom, time: Time.now, now:)
# Each QUIC connection with its HTTP/3 connection and the binding between them.
connections = {}

def respond(http3, event)
  return unless event.is_a?(Raiha::HTTP3::Event::Headers)
  path = event.headers.to_h[":path"]
  http3.send_headers(event.stream_id, [[":status", "200"], ["content-type", "text/plain"]])
  http3.send_data(event.stream_id, "hello from #{path}\n", fin: true)
end

begin
  loop do
    endpoint.each_transmit(now:) { |transmit| socket.send(transmit.payload, 0, *transmit.destination) }

    deadline = endpoint.next_timeout
    if IO.select([socket], nil, nil, deadline && [deadline - now, 0].max)
      data, address = socket.recvfrom(65535)
      route = endpoint.receive(data, from: [address[3], address[1]], now:)
      route = endpoint.admit(route.handle, now:) if route.is_a?(Raiha::QUIC::Route::Incoming)
      case route
      when Raiha::QUIC::Route::ClientHello
        quic = endpoint.accept(route.handle, tls_config:, keyring:, now:)
        http3 = Raiha::HTTP3::Connection.server
        connections[quic] = [http3, Raiha::HTTP3Binding.new(quic, http3)]
      when Raiha::QUIC::Route::Respond
        socket.send(route.transmit.payload, 0, *route.transmit.destination)
      end
    end
    deadline = endpoint.next_timeout
    endpoint.handle_timeout(now:) if deadline && now >= deadline

    connections.each do |quic, (http3, binding)|
      quic.each_event { |event| binding.receive(event, now:) }
      binding.flush(now:)
      http3.each_event { |event| respond(http3, event) }
      binding.flush(now:)
    end
    connections.delete_if { |quic, _| quic.closed? }
  end
rescue Interrupt
  connections.each_key { |quic| quic.close(error_code: Raiha::HTTP3::ErrorCode::NO_ERROR, now:) }
  endpoint.each_transmit(now:) { |transmit| socket.send(transmit.payload, 0, *transmit.destination) }
end
```

[Getting started](docs/getting-started.md) walks through this server and a client for it.

## Documentation

- [Getting started](docs/getting-started.md)
- [HTTP/3 server](docs/http3-server.md): the loop, requests and responses, stopping, 0-RTT
- [HTTP/3 client](docs/http3-client.md): requests, several requests on one connection, resumption and 0-RTT
- [QUIC](docs/quic.md): the QUIC core without HTTP/3, DATAGRAM frames
- [Fiber scheduler](docs/fiber-scheduler.md): the runtime, Rack and Ractor workers
- [Threads](docs/threads.md): the runtime on threads, with no Fiber scheduler
- [Configuration](docs/configuration.md): QUIC and TLS settings, certificates
- [qlog](docs/qlog.md)
- [Platforms](docs/platforms.md): what differs between Linux and OpenBSD
- [Development](docs/development.md): tests, type checks and interop testing

The [examples](examples/) directory has scripts that run on their own.

## License

Raiha is licensed under the [Apache License, Version 2.0](LICENSE).
