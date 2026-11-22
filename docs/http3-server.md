# HTTP/3 server

Raiha's HTTP/3 does no I/O of its own. A server is three pieces joined by a loop that you write:

- `Raiha::QUIC::Endpoint` takes the datagrams of a UDP socket and turns new clients into `Raiha::QUIC::Connection`s.
- `Raiha::HTTP3::Connection.server` is the HTTP/3 of one of those connections: it takes the bytes of streams and gives back requests as events.
- `Raiha::HTTP3Binding` joins one QUIC connection and its HTTP/3 connection: it carries QUIC's stream events and bytes to HTTP/3, and what HTTP/3 writes to QUIC.

The loop below blocks its thread on `IO.select` and needs no Fiber scheduler. Under a Fiber scheduler, `Raiha::Runtime::HTTP3::Server` runs this loop for you, with less code; see [fiber-scheduler.md](fiber-scheduler.md). The QUIC side of the loop (routes, Retry, timers) is described in [quic.md](quic.md), and the TLS and QUIC settings in [configuration.md](configuration.md).

## A complete server

This server answers every request with `200` and `hello from <path>`. It loads `cert.pem` (the chain, leaf first) and `key.pem`, and stops on Ctrl-C.

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

The client in [http3-client.md](http3-client.md) talks to it, and so does a curl built with HTTP/3: `curl -k --http3-only https://127.0.0.1:4433/`.

`ecn_address_families: []` and `enable_pmtud: false` are for the plain `UDPSocket`, which neither marks ECN nor keeps IP from fragmenting path MTU probes; see [quic.md](quic.md#a-plain-socket).

## The loop

Each pass of the loop does the same things in the same order:

1. Send what is due: `endpoint.each_transmit` gives every datagram the endpoint and its connections have to send.
2. Wait for a datagram, or until `endpoint.next_timeout`, the clock time the next timer is due (`nil` when none is). The clock is any monotonic clock in seconds, passed as `now:` to every call.
3. Hand a datagram to `endpoint.receive`, and act on the route it returns. A new client comes as `Route::Incoming`, which `admit` turns into `Route::ClientHello` once its ClientHello is whole; `accept` makes it a connection. `Route::Respond` is a datagram the endpoint answers itself. [quic.md](quic.md) covers the routes, Retry and refusing clients.
4. Once `next_timeout` has come, run the timers with `handle_timeout`, whether or not a datagram came, so that a socket that never falls quiet does not hold off loss recovery and the idle timeout.
5. For each connection, give its QUIC events to `binding.receive`, then `binding.flush`, take the HTTP/3 events, and `binding.flush` again so that what you wrote goes to QUIC.

`binding.receive(event, now:)` returns whether the event was HTTP/3's alone (stream data and stream state). The others are for you as well: `Raiha::QUIC::Event::Connected` when the handshake completes, at which point the binding opens HTTP/3's control and QPACK streams, and `Raiha::QUIC::Event::Closed` when the connection is over.

`binding.flush(now:)` reads every stream with data into HTTP/3, carries out what HTTP/3 asks of QUIC (resetting streams, stopping them, priorities, closing the connection on a protocol error), and writes what HTTP/3 has for each stream. Call it after anything you give HTTP/3, before the next `each_transmit`.

A flush can bring HTTP/3 events of its own: `Raiha::HTTP3::Event::Writable` comes out of the second flush, after the events were taken. A server that writes bodies larger than the stream takes at once has to go round until a pass brings no event:

```ruby
connections.each do |quic, (http3, binding, handler)|
  quic.each_event { |event| binding.receive(event, now:) }
  loop do
    binding.flush(now:)
    taken = 0
    http3.each_event { |event| handler.call(event); taken += 1 }
    handler.write_more
    break if taken.zero?
  end
end
```

## Requests

Each request comes on a bidirectional stream the client opened (IDs 0, 4, 8, and so on, for each connection) as a series of events:

| Event | Fields | What it means |
| --- | --- | --- |
| `Raiha::HTTP3::Event::Headers` | `stream_id`, `headers`, `fin` | The header section of a request: `[name, value]` pairs, the pseudo-header fields (`:method`, `:scheme`, `:authority`, `:path`) first. `fin` when the request has no body. |
| `Raiha::HTTP3::Event::Data` | `stream_id`, `data`, `fin` | Some of the body, as it came. `fin` when the body ends here, which may come with empty `data`. |
| `Raiha::HTTP3::Event::Trailers` | `stream_id`, `headers` | The trailer section, which ends the request. |
| `Raiha::HTTP3::Event::Reset` | `stream_id`, `error_code` | The client reset the request; nothing more of it comes. |
| `Raiha::HTTP3::Event::Stopped` | `stream_id`, `error_code` | The client asked the server to stop sending the response; nothing more goes. |
| `Raiha::HTTP3::Event::Writable` | `stream_id` | `send_data` takes more on the stream, after it took less than given. |
| `Raiha::HTTP3::Event::Settings` | `settings` | The client's SETTINGS came; also `http3.peer_settings`. |
| `Raiha::HTTP3::Event::GoAway` | `stream_id` | The client goes away. |
| `Raiha::HTTP3::Event::Blocked` | `stream_id` | A header section waits for the QPACK encoder stream, which can happen only when `qpack_max_table_capacity` is above 0. Its `Headers` or `Trailers` follow once it can be decoded; there is nothing to do. |
| `Raiha::HTTP3::Event::Datagram` | `stream_id`, `payload` | An HTTP Datagram (RFC 9297) for the request, with `h3_datagram` in the SETTINGS. |
| `Raiha::HTTP3::Event::Capsule` | `stream_id`, `capsule` | A capsule other than DATAGRAM on the stream of an Extended CONNECT request (RFC 9297). |

A malformed request never reaches you: HTTP/3 resets its stream with `H3_MESSAGE_ERROR`. A request over `max_field_section_size` is answered with 431 by HTTP/3 itself.

Events of different requests interleave, so keep what has come of each request by stream ID, per connection. This handler reads each request whole, body and trailers included, then answers it:

```ruby
# The requests of one HTTP/3 connection by stream ID, and the response
# bodies their streams have not taken all of yet.
class Handler
  def initialize(http3)
    @http3 = http3
    @requests = {}
    @unsent = {}
    @writable = []
  end

  def busy? = !@requests.empty? || !@unsent.empty?

  def call(event)
    case event
    when Raiha::HTTP3::Event::Headers
      @requests[event.stream_id] = { headers: event.headers, body: +"", trailers: [] }
      answer(event.stream_id) if event.fin
    when Raiha::HTTP3::Event::Data
      request = @requests[event.stream_id] or return
      request[:body] << event.data
      answer(event.stream_id) if event.fin
    when Raiha::HTTP3::Event::Trailers
      request = @requests[event.stream_id] or return
      request[:trailers] = event.headers
      answer(event.stream_id)
    when Raiha::HTTP3::Event::Writable
      @writable << event.stream_id
    when Raiha::HTTP3::Event::Reset, Raiha::HTTP3::Event::Stopped
      @requests.delete(event.stream_id)
      @unsent.delete(event.stream_id)
    end
  end

  # Writes more of each body whose stream takes more, once a pass's events
  # are all taken: an event after a Writable may have stopped its stream.
  def write_more
    @writable.each { |stream_id| (data = @unsent.delete(stream_id)) && write(stream_id, data) }
    @writable.clear
  end

  private def answer(stream_id)
    request = @requests.delete(stream_id)
    method, path = request[:headers].to_h.values_at(":method", ":path")
    @http3.send_headers(stream_id, [[":status", "200"], ["content-type", "text/plain"]])
    if path == "/big"
      write(stream_id, "x" * 1_000_000)
    else
      write(stream_id, "#{method} #{path}: #{request[:body].bytesize} bytes, trailers #{request[:trailers].inspect}\n")
    end
  end

  # Writes `data` and ends the stream; what the stream does not take now
  # waits for Raiha::HTTP3::Event::Writable.
  private def write(stream_id, data)
    taken = @http3.send_data(stream_id, data, fin: true)
    @unsent[stream_id] = data.byteslice(taken..) if taken < data.bytesize
  end
end
```

Make one per connection, `connections[quic] = [http3, Raiha::HTTP3Binding.new(quic, http3), Handler.new(http3)]`, and drive it with the loop of the previous section.

Two orderings to keep in mind. A `Writable` can come before a `Stopped` of the same stream in one pass, and `send_data` on a stopped stream raises `Raiha::HTTP3::Error::Usage`; that is why the handler writes only once the pass's events are all taken. And after you let a request go (below), `Data` events that were already queued for it still come, so look a request up before using it.

## Responses

- `http3.send_headers(stream_id, headers, fin: false)` sends the response's header section. `headers` is an Array of `[name, value]` Strings, lowercase names, `[":status", "200"]` first. A malformed section raises `ArgumentError`. A status of 1xx is an interim response, which may come before the final one and cannot end the stream: `send_headers(stream_id, [[":status", "103"], ["link", "</style.css>; rel=preload"]])`.
- `http3.send_data(stream_id, data, fin: false)` sends content and returns how many bytes it took. It holds at most `max_send_buffer` bytes for the stream (64 KiB unless given to `Connection.server`); with less taken than given, `Writable` tells when to give the rest, and `fin` applies only once all of it is taken.
- `send_headers` once the body has begun sends the trailer section, which always ends the stream. Send it only after `send_data` took all of the body:

```ruby
http3.send_headers(stream_id, [[":status", "200"]])
http3.send_data(stream_id, "abc")
http3.send_headers(stream_id, [["x-sum", "3"]])
```

To answer without reading the rest of the body, `http3.stop_reading(stream_id)` asks the client to stop sending it with `H3_NO_ERROR`; what of it still comes is dropped, and the response goes on:

```ruby
http3.stop_reading(stream_id)
http3.send_headers(stream_id, [[":status", "413"]], fin: true)
```

`http3.cancel(stream_id, error_code: Raiha::HTTP3::ErrorCode::REQUEST_CANCELLED)` drops a request both ways, resetting the stream.

### Priority

A request's `priority` header field (RFC 9218) sets the urgency and incrementality its response is sent with, and a `priority` field in the response's header section overrides what it gives. PRIORITY_UPDATE frames from the client are applied as they come. `http3.update_priority(stream_id, urgency: 1)` changes it from the server's side while the request is open; it raises `Raiha::HTTP3::Error::Usage` for a stream with no request. The binding passes priorities on to QUIC, which sends the streams of lower urgency first.

## Stopping

To stop gracefully (RFC 9114 "Connection Shutdown"), send each connection a GOAWAY, keep serving the requests already taken, then close. `http3.goaway` gives the lowest ID of a request not seen yet; HTTP/3 rejects requests from there on with `H3_REQUEST_REJECTED`. A connection whose handshake has not completed has no control stream yet, and `goaway` raises `Raiha::HTTP3::Error::Usage`: close it at once.

The GOAWAY has to be sent before the connection closes, since a closing QUIC connection sends nothing but its CONNECTION_CLOSE. With one pass of the loop as a lambda that waits no longer than `longest` seconds, the end of the server becomes:

```ruby
serve = lambda do |longest = nil|
  endpoint.each_transmit(now:) { |transmit| socket.send(transmit.payload, 0, *transmit.destination) }
  deadline = endpoint.next_timeout
  wait = [deadline && [deadline - now, 0].max, longest].compact.min
  if IO.select([socket], nil, nil, wait)
    # ... as in the complete server, with Handler.new(http3) for each new connection
  end
  deadline = endpoint.next_timeout
  endpoint.handle_timeout(now:) if deadline && now >= deadline
  # ... each connection's events, as in "The loop"
  connections.delete_if { |quic, _| quic.closed? }
end

begin
  loop { serve.call }
rescue Interrupt
  connections.each do |quic, (http3, binding, _)|
    http3.goaway
    binding.flush(now:)
  rescue Raiha::HTTP3::Error::Usage
    # No control stream yet: the handshake has not completed.
    quic.close(error_code: Raiha::HTTP3::ErrorCode::NO_ERROR, now:)
  end
  # A second for the GOAWAY to go, and up to five for the requests taken.
  stopping = now
  serve.call(0.1) while now - stopping < 1 || (now - stopping < 5 && connections.each_value.any? { |_, _, handler| handler.busy? })
  connections.each_key { |quic| quic.close(error_code: Raiha::HTTP3::ErrorCode::NO_ERROR, now:) }
  endpoint.each_transmit(now:) { |transmit| socket.send(transmit.payload, 0, *transmit.destination) }
end
```

Close with `Raiha::HTTP3::ErrorCode::NO_ERROR` (`H3_NO_ERROR`), the application error code of HTTP/3; QUIC's own `NO_ERROR` is not one.

## Settings and 0-RTT

`Raiha::HTTP3::Connection.server(settings:)` takes the SETTINGS the server sends, a `Raiha::HTTP3::Settings`:

| Keyword | Default | Meaning |
| --- | --- | --- |
| `qpack_max_table_capacity` | `0` | The QPACK dynamic table the client may use; 0 is none. With a table, a request's header section may wait for the encoder stream (`Raiha::HTTP3::Event::Blocked`). |
| `qpack_blocked_streams` | `0` | How many streams may wait so. |
| `max_field_section_size` | `65536` | The longest header or trailer section taken. |
| `h3_datagram` | `false` | HTTP Datagrams (RFC 9297), which also need QUIC's `max_datagram_frame_size`. |
| `enable_connect_protocol` | `false` | Extended CONNECT (RFC 9220). |

`Connection.server` without `settings:` uses `Raiha::HTTP3::Settings.new(enable_connect_protocol: true)`, which takes Extended CONNECT.

0-RTT needs a TLS config that issues tickets and allows early data, a record of the 0-RTT taken, and the same SETTINGS for the tickets and the connections (RFC 9114 "Initialization"): HTTP/3 takes 0-RTT only from a ticket issued with the SETTINGS the connection has. The ticket keys and the record are described in [configuration.md](configuration.md).

```ruby
settings = Raiha::HTTP3::Settings.new
tls_config = Raiha::TLS::Config.server(
  profile: Raiha::TLS::Profile::QUIC,
  alpn: ["h3"],
  registry: Raiha::TLS::Extension::Registry::BUILTIN.with(Raiha::QUIC::TransportParameters::Extension),
  ticket_key: SecureRandom.bytes(32),
  max_early_data_size: 1
)
anti_replay = Raiha::TLS::AntiReplay::Memory.new(now: Time.now)

# For each new connection:
quic = endpoint.accept(route.handle, tls_config:, keyring:, now:, anti_replay:, app_early_data_context: settings.early_data_context)
http3 = Raiha::HTTP3::Connection.server(settings:)
```

The record takes no 0-RTT for its first 11 seconds (`Raiha::TLS::AntiReplay::WINDOW`), so that a ClientHello taken before a restart is not taken again. `quic.stream_early_data?(stream_id)` tells whether any of a request came in 0-RTT, which an attacker can replay; answering 425 (Too Early) to one that is not safe to repeat is up to you.

## qlog

`Raiha::HTTP3::Connection.server(tracer:)` takes an HTTP/3 tracer. `Raiha::HTTP3::Qlog::Tracer.new(quic_tracer)` writes HTTP/3's events into the qlog of the QUIC connection; see [qlog.md](qlog.md).
