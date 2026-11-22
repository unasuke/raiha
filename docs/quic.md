# QUIC

Raiha's QUIC core is sans-I/O: `Raiha::QUIC::Endpoint` and `Raiha::QUIC::Connection` never touch a socket, never read a clock and never wait. You hand them the datagrams that arrive and the current time, and they hand back the datagrams to send, the events that happened, and when they next need to be woken. The loop around them is yours, so a plain blocking `UDPSocket` is enough to run QUIC, with no Fiber scheduler.

Under a Fiber scheduler, `Raiha::Runtime` runs this loop for you with less code; see [fiber-scheduler.md](fiber-scheduler.md). The TLS and QUIC settings used below are described in [configuration.md](configuration.md).

## The loop

An application owes the core four things, over and over:

1. Send what it has to send: `each_transmit(now:)` yields `Raiha::QUIC::Transmit` values. Send each `payload` to its `destination` (`[host, port]`).
2. Give it each datagram that arrives: `receive(data, from: [host, port], now:)`.
3. Wake it at its deadline: `next_timeout` is a time on the monotonic clock, or `nil` when nothing is due. Once that time has come, call `handle_timeout(now:)`.
4. Take its events: `each_event` yields what happened, such as a completed handshake or a stream with data to read. A connection holds at most 4,096 events nobody has taken; past that it closes with `INTERNAL_ERROR`.

Then wait on the socket until a datagram comes or the deadline passes, and go round again.

There are two clocks:

- `now:` is the monotonic clock in Float seconds, `Process.clock_gettime(Process::CLOCK_MONOTONIC)`. Every call that can make something happen takes it.
- `time:` is the wall clock, a `Time`, given once when an endpoint or connection is made. TLS needs it for certificates and tickets, and the core moves it on by the monotonic clock from then.

Because the core does no I/O, nothing inside it blocks: a call returns at once, and whatever has to wait (for a datagram, for flow control credit, for a timer) shows up later as an event or as a `next_timeout`.

### A plain socket

Two settings of `Raiha::QUIC::Config` matter with a plain `UDPSocket`:

- `ecn_address_families: []`. A plain socket neither marks ECN nor reads it, so tell the core not to use it. Leaving `Transmit#ecn` unsent while the core counts its packets as ECT would only make the core find ECN broken.
- `enable_pmtud: false`. Path MTU probes need a socket that keeps IP from fragmenting, which a plain socket does not set up. The runtime turns this off itself where its socket cannot; see [platforms.md](platforms.md).

On a real network, sending can fail for one datagram, as with `Errno::ECONNREFUSED` after an ICMP unreachable or `Errno::EMSGSIZE`. The examples below do not rescue it; a loop that runs for long should rescue `SystemCallError` around each send and go on, since the core treats the datagram as lost. The runtime does the same.

With `max_transmit_size` left `nil` (the default), each `Transmit` is one datagram. `Transmit#source` is the local address to send from, `nil` to leave it to the OS; it matters only for a socket bound to a wildcard address on a host with several addresses.

## A complete echo

A server in a thread, taking every client on one socket, and a client in the main thread that sends `hello` on a stream and reads it back. It needs `cert.pem` and `key.pem` for `localhost` in the current directory.

```ruby
require "raiha"
require "socket"

def now = Process.clock_gettime(Process::CLOCK_MONOTONIC)

# Waits for a datagram until `deadline` (nil for no limit): [data, [host, port]], or nil.
def wait(socket, deadline)
  timeout = deadline && [deadline - now, 0].max
  return nil unless socket.wait_readable(timeout)
  data, addr = socket.recvfrom(65535)
  [data, [addr[3], addr[1]]]
end

def send_all(socket, source)
  source.each_transmit(now:) { |t| socket.send(t.payload, 0, *t.destination) }
end

registry = Raiha::TLS::Extension::Registry::BUILTIN.with(Raiha::QUIC::TransportParameters::Extension)
config = Raiha::QUIC::Config.new(ecn_address_families: [], enable_pmtud: false)

# The server: one Endpoint for its socket.
chain = OpenSSL::X509::Certificate.load(File.read("cert.pem")).map(&:to_der)
key = OpenSSL::PKey.read(File.read("key.pem")).private_to_der
identity = Raiha::TLS::Keyring::Identity.new(cert_der: chain, key_der: key)
server_tls = Raiha::TLS::Config.server(profile: Raiha::TLS::Profile::QUIC, alpn: ["echo"], registry:)
server_keyring = Raiha::TLS::Keyring.server(config: server_tls, identities: [identity])

server_socket = UDPSocket.new
server_socket.bind("127.0.0.1", 4433)
server = Raiha::QUIC::Endpoint.server(config:, random: SecureRandom, time: Time.now, now:)

Thread.new do
  received = Hash.new { |hash, key| hash[key] = +"" }
  loop do
    send_all(server_socket, server)
    if (datagram = wait(server_socket, server.next_timeout))
      data, from = datagram
      case (route = server.receive(data, from:, now:))
      when Raiha::QUIC::Route::Incoming
        route = server.admit(route.handle, now:)
        server.accept(route.handle, tls_config: server_tls, keyring: server_keyring, now:) if route.is_a?(Raiha::QUIC::Route::ClientHello)
      when Raiha::QUIC::Route::ClientHello
        server.accept(route.handle, tls_config: server_tls, keyring: server_keyring, now:)
      when Raiha::QUIC::Route::Respond
        server_socket.send(route.transmit.payload, 0, *route.transmit.destination)
      end
    end
    deadline = server.next_timeout
    server.handle_timeout(now:) if deadline && now >= deadline
    server.each_connection do |conn|
      conn.each_event do |event|
        next unless event.is_a?(Raiha::QUIC::Event::StreamReadable)
        while (chunk = conn.stream_read(event.stream_id, 65536))
          break if chunk.empty?
          received[[conn, event.stream_id]] << chunk
        end
        # nil: the client ended the stream, so echo all of it back.
        conn.stream_write(event.stream_id, received.delete([conn, event.stream_id]) || "", fin: true) if chunk.nil?
      end
    end
  end
end

# The client: an Endpoint of its own with one connection.
client_tls = Raiha::TLS::Config.client(trust_anchors: chain, profile: Raiha::TLS::Profile::QUIC, alpn: ["echo"], registry:)
socket = UDPSocket.new
socket.bind("127.0.0.1", 0)
client = Raiha::QUIC::Endpoint.client(config:, random: SecureRandom, time: Time.now, now:)
conn = client.connect(tls_config: client_tls, keyring: Raiha::TLS::Keyring.client(config: client_tls), server_name: "localhost",
  remote: ["127.0.0.1", 4433], now:)

reply = +""
done = false
until done || conn.closed?
  send_all(socket, client)
  if (datagram = wait(socket, client.next_timeout))
    client.receive(datagram[0], from: datagram[1], now:)
  end
  deadline = client.next_timeout
  client.handle_timeout(now:) if deadline && now >= deadline
  conn.each_event do |event|
    case event
    when Raiha::QUIC::Event::Connected
      stream = conn.open_stream
      conn.stream_write(stream, "hello", fin: true)
    when Raiha::QUIC::Event::StreamReadable
      while (chunk = conn.stream_read(event.stream_id, 65536))
        break if chunk.empty?
        reply << chunk
      end
      done = chunk.nil?
    end
  end
end

conn.close(now:)
send_all(socket, client)
puts reply # => hello
```

The echo writes each reply in one `stream_write`, which is enough for a short message; a longer one has to wait for credit, as [Streams](#streams) describes. [examples/udp_handshake.rb](../examples/udp_handshake.rb) and [examples/in_memory_handshake.rb](../examples/in_memory_handshake.rb) show the same loop in other shapes, the second with no socket at all.

## Clients

`Raiha::QUIC::Endpoint.client(config:, random:, time:, now:)` makes a client's endpoint, and `connect` makes a connection on it, its first Initial waiting to be sent:

```ruby
conn = endpoint.connect(tls_config:, keyring:, server_name: "localhost", remote: ["127.0.0.1", 4433], now:)
```

`connect` also takes `tracer:` and `keylog:` (see [qlog.md](qlog.md)), and `session:`, `token:` and `early_data:` for [resumption](#resumption-and-0-rtt). Feed every datagram of the socket to `endpoint.receive`; it gives each to the connection it belongs to and returns a `Raiha::QUIC::Route::Deliver`, or a `Raiha::QUIC::Route::Drop` for one that belongs to none.

`Raiha::QUIC::Connection.client(config:, tls_config:, keyring:, server_name:, remote:, time:, now:)` makes a connection with no endpoint, which you feed with `conn.receive`. Such a connection issues no connection IDs of its own, so prefer an endpoint unless you need the bare connection.

The handshake is over when `Event::Connected` comes. `conn.handshake_complete?` tells the same, and `conn.handshake_confirmed?` turns true later, once the server's HANDSHAKE_DONE arrives. `Connected#handshake` is TLS's `HandshakeComplete`, with `server_name`, `alpn`, `cipher_suite`, `group`, `resumed`, `early_data_accepted`, `peer_certificates` and `peer_verified`.

## Servers

`Raiha::QUIC::Endpoint.server(config:, random:, time:, now:)` serves every client of one socket. `receive` routes each datagram by its connection ID and returns what it did with it, as one of the `Raiha::QUIC::Route` values below (named here without their namespace, as are the `Raiha::QUIC::Event` values):

| Route | Meaning | What to do |
| --- | --- | --- |
| `Route::Deliver` | The datagram went to an existing connection (`connection`). | Nothing. |
| `Route::Incoming` | The first Initial of a new client (`handle`, `remote`, `address_validated`). | `admit`, `retry` or `refuse` the handle. |
| `Route::ClientHello` | The ClientHello of an admitted handle is whole (`handle`, `accepted`). | `accept` or `reject` the handle. |
| `Route::Respond` | The endpoint answers by itself: a Version Negotiation, a Stateless Reset, or a CONNECTION_CLOSE for a bad Retry token. | Send `transmit`. |
| `Route::Drop` | Nothing took the datagram (`reason`, such as `:unknown_connection_id`). | Nothing. |
| `nil` | The datagram was kept for, or read into, a handle that has no ClientHello to give: not admitted yet, admitted with the ClientHello still incomplete, or past its `Route::ClientHello`, which comes only once. | Nothing. |

`Route::Foreign` comes only with the connection IDs of `Runtime::Workers` and never from a plain endpoint.

A new connection takes two steps, so that turning a client down costs little:

- `admit(handle, now:)` reads the ClientHello out of the Initial packets the handle kept. It returns `Route::ClientHello` when the ClientHello is whole already, else `nil`, and a later `receive` returns the `Route::ClientHello`.
- `accept(handle, tls_config:, keyring:, now:)` makes the `Connection` and returns it. `accepted.info` tells what the ClientHello asked for (`server_name`, `alpn_protocols` and more), which you may choose the TLS config by. It also takes `tracer:`, `keylog:`, `anti_replay:` and `app_early_data_context:`.

The other answers:

- `retry(handle, now:)` sends a Retry, at the first step only. The client comes back with a token that shows it receives at its address, and that handle arrives with `address_validated` true.
- `refuse(handle, error_code: Raiha::QUIC::ErrorCode::CONNECTION_REFUSED)` closes the offer with a transport error, at either step.
- `reject(handle, description)` turns down a whole ClientHello with a TLS alert, one of `:unrecognized_name`, `:missing_extension`, `:no_application_protocol`, `:handshake_failure`, `:insufficient_security`, `:internal_error` and `:general_error`.

The endpoint bounds what each offer keeps, but not how many connections there are. Count your connections and offers whose address is not validated (`conn.address_validated?`, `route.address_validated`), and `retry` new clients once that count reaches a limit of your own: clients that spoof their address are never validated, and would otherwise take every connection you have room for. An offer nobody decides on goes after 10 seconds.

`each_connection` yields every connection of the endpoint and `connection_count` counts them. `endpoint.each_transmit`, `next_timeout` and `handle_timeout` cover all of them and the offers, and `handle_timeout` lets go of the connections that have closed.

## Events

`each_event` (or `next_event`, one at a time) gives these `Raiha::QUIC::Event` values:

| Event | Fields | Meaning |
| --- | --- | --- |
| `Connected` | `handshake` | The handshake completed. |
| `StreamReadable` | `stream_id` | The stream has data to read, or its end. |
| `StreamWritable` | `stream_id` | A stream that took only part of a write can take more. |
| `StreamReset` | `stream_id`, `error_code`, `final_size` | The peer abandoned sending on the stream (RESET_STREAM). |
| `StopSending` | `stream_id`, `error_code` | The peer asks this end to stop sending on the stream. |
| `DatagramReceived` | `data` | A DATAGRAM frame arrived. |
| `KeyUpdated` | `phase` | The 1-RTT keys were updated. |
| `SessionTicket` | `session` | At a client, a `Raiha::QUIC::Session` to resume later. |
| `NewToken` | `token` | At a client, a token for later connections to this server. |
| `ZeroRttRejected` | `reason` | At a client, the server took no 0-RTT. |
| `TLSEvent` | `event` | A TLS event passed on as it came. |
| `Closed` | `error`, `by_peer` | The connection closed. `error` is a `Raiha::QUIC::ConnectionError`. |

## Streams

Stream IDs are Integers, as QUIC numbers them. A connection opens streams, writes and reads them by ID:

| Method | What it does |
| --- | --- |
| `open_stream(direction: :bidi)` | Opens a stream, `:bidi` or `:uni`, and returns its ID, or `nil` while the peer allows no more. |
| `stream_write(id, data, fin: false)` | Takes as much of `data` as flow control and the send buffer allow and returns how many bytes it took. With `fin: true`, the stream ends once all of `data` is taken. |
| `stream_writable_bytes(id)` | How many bytes a write would take now. |
| `stream_read(id, max_bytes)` | Up to `max_bytes` that arrived: `""` when nothing is there yet, `nil` once the stream has ended. What is read goes back to the peer as flow control credit. |
| `readable_streams` | The IDs a read would give something on. |
| `writable_streams` | The IDs a write would take something on. |
| `stream_reset(id, error_code:)` | Abandons sending (RESET_STREAM); what was not acknowledged is not sent again. |
| `stream_stop_sending(id, error_code:)` | Asks the peer to stop sending (STOP_SENDING); what still comes is dropped. |
| `stream_priority(id, urgency:, incremental:)` | Sends streams of a lower urgency (0 to 7) first; within one urgency, incremental streams take turns. A stream is urgency 3 and incremental unless told. |

When `stream_write` takes less than all of `data`, keep the rest and write it when `Event::StreamWritable` comes for that stream. That event comes once per partial write. Read a stream on `Event::StreamReadable` until `stream_read` gives `""` (more later) or `nil` (the end). Data you do not read holds the peer back, as its credit comes back only as you read.

`conn.stream_early_data?(id)` tells, at a server, whether part of the stream came in 0-RTT and so may be a replay.

## DATAGRAM frames

To exchange DATAGRAM frames (RFC 9221), both ends set `max_datagram_frame_size` in their `Raiha::QUIC::Config`; RFC 9221 suggests `65535`. Then:

- `datagram_send(data, expires_at: nil, urgency: 3)` queues `data` for one DATAGRAM frame, never sent again if lost, and returns whether it was queued. It is not queued when the peer takes no DATAGRAM frames, when `data` is over `datagram_max_size`, or when too many wait. With `expires_at` (a monotonic time), it is dropped unsent past that time.
- `datagram_max_size` is the largest `data` a frame can carry now, or `nil` while the peer has not agreed to DATAGRAM frames. It depends on the path, so it can change.
- `Event::DatagramReceived` carries each DATAGRAM that arrives.

## Closing

`conn.close(error_code: 0, reason: "", now:)` closes with an application error code; `application: false` makes it a transport error. A CONNECTION_CLOSE goes out at the next `each_transmit`, and the connection stays closing for three PTOs, answering what still comes. Keep running the loop until `conn.closed?`; `closing?` and `draining?` tell the state on the way. An endpoint lets a connection go at the `handle_timeout` after it has closed.

`conn.close_reason` is `nil` while the connection is open, then the `Raiha::QUIC::ConnectionError` it closed with: `code`, `reason`, `application`, and `frame_type` (`nil` for an application error). `Event::Closed` carries the same, with `by_peer`. A connection also closes on its own at its idle timeout (`max_idle_timeout`), or on a stateless reset from the peer.

## Resumption and 0-RTT

A client keeps what the server sends for later connections:

- `Event::SessionTicket` gives a `Raiha::QUIC::Session`. `session.to_h` and `Raiha::QUIC::Session.from_h` turn it into plain values and back, for storing.
- `Event::NewToken` gives a token that lets a later connection skip address validation.

Pass them to a later `connect(..., session:, token:)` to resume, and add `early_data: true` to send 0-RTT. What streams and DATAGRAM frames carry before the handshake completes then goes in 0-RTT packets. An attacker can replay 0-RTT, so send in it only what is safe to repeat. Use each ticket and token for one connection only.

`conn.zero_rtt_state` is `:disabled`, `:pending` while 0-RTT goes, then `:accepted` or `:rejected`. On a rejection, `Event::ZeroRttRejected` comes and the streams opened in 0-RTT are gone; until you call `conn.acknowledge_zero_rtt_rejection`, those streams and `open_stream` raise `Raiha::QUIC::Error::ZeroRttRejected`. What to send again is up to you.

A server takes 0-RTT when its TLS config has ticket keys and `max_early_data_size` (see [configuration.md](configuration.md#tickets-and-0-rtt)). Its `accept` must then be given an `anti_replay:` record, such as `Raiha::TLS::AntiReplay::Memory.new(now: Time.now)`, so that each ClientHello's 0-RTT is taken at most once; without one, `accept` raises `Raiha::TLS::UsageError`.

## Statistics and tracing

`conn.stats` returns a `Raiha::QUIC::Stats`: `rtt`, `rtt_var`, `min_rtt`, `congestion_window`, `bytes_in_flight`, `packets_sent`, `packets_received`, `packets_lost`, `packets_spuriously_lost`, `bytes_sent`, `bytes_received`, `path_mtu`, `handshake_duration`, `receive_window`, `send_buffer_bytes`, `blocked_sent` and `blocked_received`.

`tracer:` on `connect` and `accept` takes a qlog tracer, and `keylog:` a writer of TLS secrets; see [qlog.md](qlog.md).
