# Getting started

This guide runs an HTTP/3 server on the loopback interface and fetches a page from it with Raiha's own client. Both are plain Ruby scripts that block on their UDP sockets; neither needs a Fiber scheduler.

## Setup

Add Raiha to your Gemfile and run `bundle install`:

```ruby
gem "raiha"
```

QUIC always runs over TLS, so the server needs a certificate. For trying things out, make a self-signed one for `localhost`:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem -out cert.pem -days 30 -subj /CN=localhost -addext subjectAltName=DNS:localhost
```

## The server

Save this as `server.rb`:

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

What each part does:

- `Raiha::TLS::Keyring::Identity` is a certificate chain and its private key, both DER-encoded. `cert.pem` may hold the whole chain, leaf first.
- `Raiha::TLS::Config.server` is the TLS side. `Raiha::TLS::Profile::QUIC` sets TLS up as QUIC needs it, `alpn` offers HTTP/3 (`"h3"`), and the registry adds the QUIC transport parameters extension to the TLS extensions Raiha knows. `Raiha::TLS::Keyring.server` holds the identities the server can present.
- `Raiha::QUIC::Endpoint.server` is the QUIC side of the socket. It does no I/O: the loop gives it each datagram with `receive` and sends what `each_transmit` gives. `now` is a monotonic clock in seconds, passed to every call, and `Raiha::QUIC::Config.new` takes the transport settings ([Configuration](configuration.md) lists them). A plain `UDPSocket` can neither mark ECN nor keep IP from fragmenting path MTU probes, so the example turns both off with `ecn_address_families: []` and `enable_pmtud: false`.
- `receive` returns a route. A new client's first datagrams come as `Raiha::QUIC::Route::Incoming`; `admit` turns it into `Raiha::QUIC::Route::ClientHello` once the ClientHello is whole, and `accept` makes it a `Raiha::QUIC::Connection`.
- `Raiha::HTTP3::Connection.server` is the HTTP/3 of that connection, and `Raiha::HTTP3Binding` carries stream data between the two. Each pass gives the QUIC events to the binding, flushes it, takes the HTTP/3 events, and flushes again so that the response goes to QUIC.
- `respond` answers each request's header section with `send_headers` and `send_data`; headers are an array of `[name, value]` pairs with lowercase names.
- Once `endpoint.next_timeout` has come, `handle_timeout` runs the timers (retransmission, the idle timeout and so on), whether or not a datagram came.
- Ctrl-C closes every connection with `H3_NO_ERROR` and sends the CONNECTION_CLOSE frames.

Run it:

```sh
bundle exec ruby server.rb
```

[HTTP/3 server](http3-server.md) goes through the loop in detail.

## The client

Save this as `client.rb` and run it with `bundle exec ruby client.rb` while the server runs:

```ruby
require "raiha"
require "socket"

def now = Process.clock_gettime(Process::CLOCK_MONOTONIC)

tls_config = Raiha::TLS::Config.client(
  trust_anchors: [OpenSSL::X509::Certificate.new(File.read("cert.pem")).to_der],
  profile: Raiha::TLS::Profile::QUIC,
  alpn: ["h3"],
  registry: Raiha::TLS::Extension::Registry::BUILTIN.with(Raiha::QUIC::TransportParameters::Extension)
)

socket = UDPSocket.new
socket.bind("127.0.0.1", 0)
quic = Raiha::QUIC::Connection.client(config: Raiha::QUIC::Config.new(ecn_address_families: [], enable_pmtud: false), tls_config:, keyring: Raiha::TLS::Keyring.client(config: tls_config),
  server_name: "localhost", remote: ["127.0.0.1", 4433], time: Time.now, now:)
http3 = Raiha::HTTP3::Connection.client
binding = Raiha::HTTP3Binding.new(quic, http3)

status = nil
body = +""
done = false

until done || quic.closed?
  quic.each_transmit(now:) { |transmit| socket.send(transmit.payload, 0, *transmit.destination) }
  deadline = quic.next_timeout
  if IO.select([socket], nil, nil, deadline && [deadline - now, 0].max)
    data, address = socket.recvfrom(65535)
    quic.receive(data, from: [address[3], address[1]], now:)
  end
  deadline = quic.next_timeout
  quic.handle_timeout(now:) if deadline && now >= deadline

  quic.each_event do |event|
    binding.receive(event, now:)
    next unless event.is_a?(Raiha::QUIC::Event::Connected)
    request = [[":method", "GET"], [":scheme", "https"], [":authority", "localhost"], [":path", "/hello"]]
    http3.send_request(quic.open_stream, request, fin: true)
  end
  binding.flush(now:)
  http3.each_event do |event|
    case event
    when Raiha::HTTP3::Event::Headers
      status = event.headers.to_h[":status"]
      done = event.fin
    when Raiha::HTTP3::Event::Data
      body << event.data
      done = event.fin
    when Raiha::HTTP3::Event::Trailers, Raiha::HTTP3::Event::Reset
      done = true
    end
  end
  binding.flush(now:)
end

quic.close(error_code: Raiha::HTTP3::ErrorCode::NO_ERROR, now:)
quic.each_transmit(now:) { |transmit| socket.send(transmit.payload, 0, *transmit.destination) }
puts status, body
```

It prints:

```
200
hello from /hello
```

The client trusts only the certificates in `trust_anchors`, here the self-signed one, and checks the server's certificate for `server_name`. Its loop is the server's for one connection: once the handshake completes (`Raiha::QUIC::Event::Connected`), it opens a stream and sends the request on it, then gathers the response's events until the response ends. [HTTP/3 client](http3-client.md) explains why it checks for the end right after taking the events.

A curl built with HTTP/3 support can ask the server too: `curl -k --http3-only https://127.0.0.1:4433/`.

## Next steps

- [HTTP/3 server](http3-server.md): the loop, request bodies, large responses, trailers, stopping and 0-RTT
- [HTTP/3 client](http3-client.md): request bodies, several requests on one connection, resumption and 0-RTT
- [QUIC](quic.md): the sans-I/O QUIC core without HTTP/3
- [Fiber scheduler](fiber-scheduler.md): the runtime, which runs these loops for you under a Fiber scheduler such as the `async` gem, with Rack and Ractor workers
- [Configuration](configuration.md): transport settings, certificates, resumption and 0-RTT
- [qlog](qlog.md): tracing connections
