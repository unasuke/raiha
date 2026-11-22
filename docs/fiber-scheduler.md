# Fiber scheduler

The pages on [QUIC](quic.md), the [HTTP/3 server](http3-server.md) and the [HTTP/3 client](http3-client.md) drive the protocols with a loop of your own: send what the connection has to send, feed it the datagrams that arrive, and call it again at its next timeout. `Raiha::Runtime` is that loop written once, for a Fiber scheduler. It owns the UDP sockets and the timers, runs each connection, stream and request in a fiber of its own, and gives the application calls that read as if they blocked: `stream.read` waits for data, `request.respond` waits while flow control holds the response back. Only the fiber that makes a call waits; the others go on.

## The scheduler

The runtime waits through `Fiber.scheduler`, which Ruby leaves to a gem. The examples here use the [async](https://github.com/socketry/async) gem, which Raiha does not depend on; add it to your Gemfile:

```ruby
gem "async"
```

Call the runtime inside `Sync do ... end` or `Async do ... end`. `Runtime::Server#run`, `Runtime::HTTP3::Server#run` and `Runtime::Client.connect` raise `Raiha::Runtime::Error::Usage` on a thread with no scheduler. To run with no scheduler, on threads, use `Raiha::Runtime::Threaded`; see [Threads](threads.md).

The async gem reads sockets with `IO::Buffer`, which Ruby 4.0 warns is experimental. Set `Warning[:experimental] = false` before `require "async"` to silence it.

The server and the client share the scheduler with the rest of the application: run a server in an `Async` task and other tasks go on beside it, as the [QUIC echo](#a-minimal-echo) below does with a server and a client in one process. `stop` takes no lock and does not block, so it can be called from a signal handler or from another fiber.

## HTTP/3 server

### A minimal server

```ruby
require "raiha"
require "async"

registry = Raiha::TLS::Extension::Registry::BUILTIN.with(Raiha::QUIC::TransportParameters::Extension)
tls = Raiha::TLS::Config.server(profile: Raiha::TLS::Profile::QUIC, alpn: ["h3"], registry:)
identity = Raiha::TLS::Keyring::Identity.new(
  cert_der: OpenSSL::X509::Certificate.load(File.read("fullchain.pem")).map(&:to_der),
  key_der: OpenSSL::PKey.read(File.read("privkey.pem")).private_to_der
)
keyring = Raiha::TLS::Keyring.server(config: tls, identities: [identity])

server = Raiha::Runtime::HTTP3::Server.new(config: Raiha::QUIC::Config.new, tls_config: tls, keyring:, host: "::", port: 4433)
trap("INT") { server.stop }

Sync do
  server.run do |request|
    request.respond(200, [["content-type", "text/plain"]], "hello from #{request.path}\n")
  end
end
```

What each piece is:

- The TLS `Config` uses the QUIC profile, offers `"h3"` by ALPN, and carries the extension registry with QUIC's transport parameters. See [configuration.md](configuration.md) for the TLS and QUIC settings.
- A `Keyring::Identity` is a certificate chain, leaf first, and its private key. `OpenSSL::X509::Certificate.load` reads every certificate of a PEM file. A `Keyring` holds the parsed identities; build one per process or Ractor, not per connection.
- `host` defaults to `"::"` and `port` to `443`. On a system where `"::"` does not take IPv4, the server binds `"0.0.0.0"` on the same port as well (see [platforms.md](platforms.md)).
- `run` blocks until the server stops. `stop` may be called from a signal handler.

### Server options

`Runtime::HTTP3::Server.new` takes:

| Keyword | Default | Meaning |
| --- | --- | --- |
| `config:` | required | The `QUIC::Config` of the connections. |
| `tls_config:` | required | A server `TLS::Config` with `"h3"` in `alpn`. |
| `keyring:` | required | `TLS::Keyring.server` for that config. |
| `host:` | `"::"` | Address to bind. |
| `port:` | `443` | Port to bind; `0` picks a free one. |
| `max_connections:` | `1024` | Connections served at once. More are refused with `CONNECTION_REFUSED`. |
| `max_unvalidated:` | half of `max_connections` | Once this many connections have unvalidated addresses, new clients are sent a Retry first. `0` sends one to every client without a token. |
| `qlog_dir:` | `nil` | A directory to write a qlog of each connection to. See [qlog.md](qlog.md). |
| `settings:` | `Raiha::HTTP3::Settings.new` | The server's HTTP/3 SETTINGS. |
| `anti_replay:` | a `TLS::AntiReplay::Memory` of its own | The record of 0-RTT ClientHellos, so that each is taken at most once. |
| `worker:` | `nil` | The `Worker` given by `Workers`. See [Workers](#several-ractors-with-workers). Do not give `host` or `port` with it. |

`Raiha::HTTP3::Settings.new` takes `qpack_max_table_capacity:` (0), `qpack_blocked_streams:` (0), `max_field_section_size:` (65,536), `h3_datagram:` (false) and `enable_connect_protocol:` (false).

Other methods:

- `local_address` is `[address, port]` once `run` has bound the socket, and `nil` before. With `port: 0`, use it to learn the port.
- `stop(timeout: 30)` stops the server. See [Stopping](#stopping).
- `reconfigure(tls_config:, keyring:)` makes connections from now on use another TLS config and keyring, for a renewed certificate. Connections already taken keep theirs.

### Requests

The block is called once per request, in a fiber of its own, with a `Runtime::HTTP3::Request`. A slow request does not hold up the others.

| Method | Value |
| --- | --- |
| `method`, `path` | The `:method` and `:path` pseudo-header fields (`""` if absent). |
| `authority`, `scheme`, `protocol` | `:authority`, `:scheme` and `:protocol`, or `nil`. `protocol` is set only for an Extended CONNECT. |
| `headers` | The header fields without the pseudo-header ones, as `[[name, value], ...]`. Names are lowercase. A field that appears more than once stays as separate pairs. |
| `body` | The request body as it arrives (below). |
| `trailers` | The trailer fields, once the body has been read to its end; `[]` until then or if there are none. |
| `stream_id` | The QUIC stream of the request. |
| `early_data?` | Whether the request may be a replay. See [Early data](#early-data-0-rtt). |
| `responded?` | Whether `respond` has been called. |

The body is read as it comes:

- `request.body.read_chunk` returns the next chunk, waiting for it, and `nil` at the end.
- `request.body.each { |chunk| ... }` yields each chunk until the end.
- `request.body.read` returns everything that is left as one String.

The server keeps at most 256 KiB of the body unread. Past that, it stops reading the stream and QUIC flow control holds the client back. A body you never read is not buffered without limit. When the request is over, the client is told to stop sending what is left of the body.

```ruby
server.run do |request|
  case [request.method, request.path]
  in ["POST", "/upload"]
    size = 0
    request.body.each { |chunk| size += chunk.bytesize }
    request.respond(200, [["content-type", "text/plain"]], "#{size} bytes, trailers #{request.trailers.inspect}\n")
  in ["GET", "/stream"]
    request.priority = { urgency: 5, incremental: true }
    request.respond(200, [["content-type", "text/plain"]]) do |body|
      3.times { |i| body << "part #{i}\n" }
      body.trailers = [["x-parts", "3"]]
    end
  in ["POST", "/order"] if request.early_data?
    request.respond(425)
  else
    request.respond(404, [], "not found\n")
  end
end
```

### Responses

`request.respond(status, headers = [], body = nil)` sends a whole response:

- `status` is an Integer from 200 to 599. Anything else raises `ArgumentError`. Interim (1xx) responses cannot be sent.
- `headers` is an Array of `[name, value]` pairs. Do not include `:status`; it is added for you.
- `body` is a String or `nil`. It is written as fast as flow control allows; `respond` waits until all of it has been handed to QUIC.

A request takes one response. A second `respond` raises `Raiha::Runtime::Error::Usage`.

#### Writing the body as you go

Give `respond` a block, and the block gets a `Runtime::HTTP3::ResponseBody` to write to:

- `write(data)` or `body << data` writes a chunk. Each write waits while the client's flow control holds the stream back.
- `trailers = [[name, value], ...]` sets trailer fields, sent after the body.
- `close` ends the response, with the trailers set so far, before the block is over. After that, `write` and `trailers=` raise `Error::Usage`. `closed?` tells whether it has ended.

The response ends when the block returns, if `close` has not ended it already.

#### Priority

`request.priority = { urgency: 0..7, incremental: true/false }` sets the priority of the response (RFC 9218). The parameters given override those the request asked for; those left out keep the request's.

#### When the block does not answer

- If the block returns without calling `respond`, the request is answered with 500. An Extended CONNECT request is answered with 501.
- If the block raises before responding, the request is answered with 500. If it raises in the middle of a response, the stream is reset with `H3_INTERNAL_ERROR`. A response that was already complete is left alone. In both cases the exception goes on to the scheduler (async logs it), and the other requests and the connection go on.
- If the client resets the request, or stops reading the response, the call that is waiting on it (a body read or a write) raises `Runtime::HTTP3::StreamReset`, with `stream_id` and the HTTP/3 `error_code`. The server catches it when it leaves your block, so you need to rescue it only to clean up.
- If the connection closes, waiting calls raise `Raiha::QUIC::ClosedError`. The server catches that too.

### Early data (0-RTT)

The server takes 0-RTT only when its TLS config issues tickets and allows early data (`ticket_keys:` or `ticket_key:`, and `max_early_data_size:`; see [configuration.md](configuration.md)). It takes 0-RTT only from a ticket issued with the same HTTP/3 `settings`. Each ClientHello's 0-RTT is taken at most once, as recorded in `anti_replay:`. The default `TLS::AntiReplay::Memory` takes no 0-RTT for its first 11 seconds, so that a ClientHello taken before a restart is not taken again.

0-RTT can still be replayed by an attacker to another server, or arrive again by way of a proxy. `request.early_data?` is true when any part of the request came in 0-RTT, or when it carries an `Early-Data` header field, which a proxy adds to a request it forwarded from early data. Answering 425 (Too Early) to a request that is not safe to repeat is up to you.

### Stopping

`server.stop(timeout: 30)` asks the server to stop. Only the first call counts. It does not wait, so a signal handler may call it.

1. No new connections are taken.
2. Each connection is sent a GOAWAY, then after twice its RTT a second GOAWAY that names the first request not yet seen. Requests after that are rejected with `H3_REQUEST_REJECTED`.
3. Requests already taken are let finish, and what was sent is let be acknowledged. Then the connection closes with `H3_NO_ERROR`.
4. When `timeout` seconds have passed, requests not yet given to the block are rejected, and those in progress are cancelled with `H3_REQUEST_CANCELLED`. Their fibers get `StreamReset` where they wait, if the scheduler can interrupt fibers. Then the remaining connections close.

`run` returns once every connection has closed.

### Rack

`Raiha::Runtime::Rack` runs a Rack 3 application on the server. It is not loaded by `require "raiha"`, and it does not depend on the rack gem.

```ruby
require "raiha/runtime/rack"

app = lambda do |env|
  request = env["raiha.request"]
  [200, { "content-type" => "text/plain" }, ["#{env["REQUEST_METHOD"]} #{env["PATH_INFO"]} over #{env["SERVER_PROTOCOL"]}, ",
    "early data: #{request.early_data?}\n"]]
end

server.run(&Raiha::Runtime::Rack.new(app))
```

What the adapter does:

- `rack.input` reads the request body as it arrives. It supports `read`, `read(length)`, `gets`, `each` and `close`.
- A body that responds to `each` is written chunk by chunk. A body that responds to `call` (a streaming body) is called with a stream that reads the request (`read`) and writes the response (`write`, `<<`, `flush`). The response ends at `close_write` or `close`, even if the body goes on.
- A header value that is an Array is sent as one field line per element. Headers whose names start with `rack.` are not sent.
- The response to `HEAD` is sent without its body.
- `SERVER_PROTOCOL` is `"HTTP/3"`. `HTTP_HOST`, `SERVER_NAME` and `SERVER_PORT` come from `:authority`, or from the `host` field when there is none. A missing port is 443 for https and 80 for http.
- Repeated header fields are joined with `", "`, and `cookie` fields with `"; "`.
- A header field whose name has an underscore is left out, so that `x_forwarded_for` cannot pass for `x-forwarded-for`.
- A request whose scheme is not `http` or `https` is answered with 400.
- For an Extended CONNECT, `rack.protocol` is `[protocol]`.
- `env["raiha.request"]` is the `Runtime::HTTP3::Request`, for the trailers, `early_data?`, `priority=` and the rest.

A streaming body, echoing the request:

```ruby
echo = lambda do |env|
  [200, { "content-type" => "application/octet-stream" }, proc do |stream|
    while (chunk = stream.read(16_384))
      stream.write(chunk)
    end
    stream.close
  end]
end
```

### Several Ractors with Workers

`Raiha::Runtime::Workers` runs a server in each of several Ractors, all on one port. It binds a socket per worker with `SO_REUSEPORT`, and runs your block in each worker's Ractor with its `Worker`. The block makes a server with `worker:` and `config: worker.config`, and runs it under a Fiber scheduler of its own.

```ruby
identity = Ractor.make_shareable(Raiha::TLS::Keyring::Identity.new(
  cert_der: OpenSSL::X509::Certificate.load(File.read("fullchain.pem")).map(&:to_der),
  key_der: OpenSSL::PKey.read(File.read("privkey.pem")).private_to_der
))

workers = Raiha::Runtime::Workers.new(count: 4, config: Raiha::QUIC::Config.new, host: "::", port: 4433, args: [tls, identity]) do |worker, tls, identity|
  keyring = Raiha::TLS::Keyring.server(config: tls, identities: [identity])
  Sync do
    Raiha::Runtime::HTTP3::Server.new(config: worker.config, tls_config: tls, keyring:, worker:).run do |request|
      request.respond(200, [["content-type", "text/plain"]], "worker #{worker.id} answered #{request.path}\n")
    end
  end
end
trap("INT") { workers.stop }
workers.run
```

- The block runs in another Ractor and cannot use local variables from outside it. Pass what it needs in `args:`; each is given to the block after the worker. Arguments that are not shareable are copied.
- A `Keyring` cannot be sent to another Ractor, so pass the identities and build the keyring inside the block.
- `count` is 1 to 256. `host` defaults to `"::"` and `port` to `443`.
- The `config` is shared by all workers. If it has no `retry_token_key` or `stateless_reset_key`, one is generated for all of them, so that each worker accepts the tokens and recognizes the connection IDs that another issued. Its `connection_id_length` must be at least 4 (the default is 8), since the connection IDs carry the worker's ID.
- The workers share one record of 0-RTT, so a ClientHello's 0-RTT is taken once across all of them.
- A datagram that arrives at one worker for another worker's connection, as after a client migrates, is handed on to that worker.

Methods:

- `run` blocks until every worker is over. When one worker's block ends, the others are told to stop. If a worker raised, `run` raises the first error.
- `stop(timeout: 30)` stops every worker as `Server#stop` does. It may be called from a signal handler.
- `reconfigure(tls_config:, identities:)` makes every worker take new connections with another TLS config, building its keyring from `identities`.
- `stats(timeout: 1.0)` returns a `Worker::Stats` per worker (`id`, `sent`, `received` and `dropped` counts of datagrams handed between workers), or `nil` for a worker that does not answer in time.
- `local_address` is `[address, port]` once `run` has bound the sockets.

`SO_REUSEPORT` spreads datagrams across the sockets on Linux. On other systems, such as OpenBSD, the kernel may give them all to one socket. The worker that has it then takes every new connection, so the load is not spread. See [platforms.md](platforms.md).

## HTTP/3 client

### A minimal request

```ruby
require "raiha"
require "async"

registry = Raiha::TLS::Extension::Registry::BUILTIN.with(Raiha::QUIC::TransportParameters::Extension)
tls = Raiha::TLS::Config.client(trust_anchors: [File.read("ca.der")], profile: Raiha::TLS::Profile::QUIC, alpn: [Raiha::Runtime::HTTP3::Client::ALPN], registry:)
keyring = Raiha::TLS::Keyring.client(config: tls)

Sync do
  response = Raiha::Runtime::Client.connect("localhost", 4433, config: Raiha::QUIC::Config.new, tls_config: tls, keyring:) do |session|
    Raiha::Runtime::HTTP3::Client.new(session).get("/", headers: [["accept", "text/plain"]])
  end
  puts response.status, response.headers.inspect, response.body
end
```

- The TLS `Config` uses the QUIC profile, offers `"h3"` (`Runtime::HTTP3::Client::ALPN`) by ALPN, and carries the extension registry with QUIC's transport parameters.
- `trust_anchors` is an Array of DER-encoded CA certificates that the server's certificate is verified against. See [Trust anchors](configuration.md#trust-anchors) for the system's store.
- `Client.connect` gives the block a `Session` once the handshake completes, and returns the block's value. When the block is over, the connection is closed with `H3_NO_ERROR`.
- `HTTP3::Client.new(session)` attaches HTTP/3 to the session. Make one per connection.

### Connecting

`Runtime::Client.connect(host, port, **options) { |session| ... }` resolves `host` and tries each of its addresses in turn, with a socket of its own for each, until one completes its handshake. There is no discovery of HTTP/3 through Alt-Svc or HTTPS records, and no fallback to TCP: the host and port are taken to speak QUIC.

| Keyword | Default | Meaning |
| --- | --- | --- |
| `config:` | required | The `QUIC::Config` of the connection. See [configuration.md](configuration.md). |
| `tls_config:` | required | A client `TLS::Config` with `"h3"` in `alpn`. |
| `keyring:` | required | `TLS::Keyring.client` for that config. |
| `server_name:` | `host` | The name sent by SNI and verified against the certificate. It is also the default `:authority` of requests. |
| `connect_timeout:` | `5.0` | Seconds to wait for each address's handshake. |
| `qlog_dir:` | `nil` | A directory to write a qlog of each connection tried to. See [qlog.md](qlog.md). |
| `session:` | `nil` | A ticket to resume. See [Resumption and 0-RTT](#resumption-and-0-rtt). |
| `token:` | `nil` | An address validation token from an earlier connection. |
| `early_data:` | `false` | Send requests in 0-RTT when the ticket allows it. |

When no address completes a handshake, `connect` raises `Runtime::ConnectError`. Its `errors` has `[address, error]` for each address tried: the `Raiha::QUIC::ClosedError` of a connection that closed or ran out of time, or the error of a name that did not resolve.

```ruby
begin
  Raiha::Runtime::Client.connect("localhost", 4433, config: Raiha::QUIC::Config.new, tls_config: tls, keyring:, connect_timeout: 1) do |session|
    Raiha::Runtime::HTTP3::Client.new(session).get("/")
  end
rescue Raiha::Runtime::ConnectError => error
  error.errors.each { |address, failure| warn "#{address.inspect}: #{failure.message}" }
end
```

Once the block has started, its connection is not retried at another address. If the connection closes while the block is using it, the waiting call raises `Raiha::QUIC::ClosedError`.

`HTTP3::Client.new(session, authority: nil, settings: Raiha::HTTP3::Settings.new)` takes the `:authority` of its requests (the session's `server_name` by default) and its own HTTP/3 SETTINGS. Requests always go with `:scheme` `https`.

### Requests

`client.get(path, headers: [])` sends a GET and reads the whole response.

`client.request(method, path, headers: [], body: nil, urgency: nil, incremental: nil)` sends any request:

- `headers` is an Array of `[name, value]` pairs, without pseudo-header fields. Names must be lowercase; a malformed field, such as `["Accept", "*/*"]`, raises `ArgumentError`.
- `body` is a String, or anything that reads as an IO does (`read(length)`), such as a File. It is read 64 KiB at a time and sent as the server's flow control allows. If the server stops the request with `H3_NO_ERROR` because it does not want the rest of the body, sending stops and the response is read all the same.
- `urgency` (0 to 7) and `incremental` are sent as the `priority` header field (RFC 9218). An urgency outside 0 to 7 raises `ArgumentError`.

Without a block, `request` and `get` return a `Runtime::HTTP3::Response`, with `status` (an Integer), `headers` (without pseudo-header fields), `body` (a binary String) and `trailers` (`[]` when there are none). Interim (1xx) responses are skipped.

```ruby
Raiha::Runtime::Client.connect("localhost", 4433, config: Raiha::QUIC::Config.new, tls_config: tls, keyring:) do |session|
  client = Raiha::Runtime::HTTP3::Client.new(session)
  client.request("POST", "/form", headers: [["content-type", "application/x-www-form-urlencoded"]], body: "name=raiha")
  File.open("upload.bin", "rb") { |file| client.request("PUT", "/files/upload.bin", body: file) }
  client.request("GET", "/style.css", urgency: 1, incremental: false)
end
```

#### Several requests at once

Requests made from different fibers share the connection and run side by side:

```ruby
bodies = %w[/a /b /c].map { |path| Async { client.get(path).body } }.map(&:wait)
```

### Streaming a response

Give `request` a block, and it is called with a `Runtime::HTTP3::ResponseStream` once the response's header section has arrived. The block's value is returned.

- `status` and `headers` are those of the response.
- `body.read_chunk` returns the next chunk, waiting for it, and `nil` at the end. `body.each { |chunk| ... }` yields each chunk, and `body.read` returns all that is left.
- `trailers` is the trailer fields, once the body has been read to its end.
- `cancel` stops the request and its response with `H3_REQUEST_CANCELLED`.

```ruby
client.request("GET", "/big") do |response|
  size = 0
  response.body.each { |chunk| size += chunk.bytesize }
  [response.status, size, response.trailers]
end
```

The client keeps at most 256 KiB of the body unread. Past that, it stops reading the stream, and QUIC flow control holds the server back until the application reads more. A response the block leaves unread when it returns is cancelled.

### Errors

| Error | When |
| --- | --- |
| `Runtime::ConnectError` | `Client.connect` could not connect to any address. |
| `Runtime::HTTP3::StreamReset` | The server reset the response, or stopped the request with an error. `stream_id` and `error_code` (the HTTP/3 error code) tell which and why. The connection and other requests go on. |
| `Raiha::QUIC::ClosedError` | The connection closed. `error` has the code, whether it is an application error, and the reason. |
| `Raiha::QUIC::Error::ZeroRttRejected` | A request sent in 0-RTT was rejected by the server. See below. |
| `Runtime::Error::Usage` | A call the runtime does not allow, such as `connect` without a Fiber scheduler. |

```ruby
begin
  client.get("/reset")
rescue Raiha::Runtime::HTTP3::StreamReset => error
  warn "stream #{error.stream_id} reset with 0x#{error.error_code.to_s(16)}"
end
```

### Resumption and 0-RTT

A connection that resumes an earlier one skips the server's certificate, and may send requests in 0-RTT, before the handshake completes.

- `client.tickets` gives the session tickets the server sent, each a `Raiha::HTTP3::Session` that carries the server's SETTINGS too. There are none until the server's SETTINGS have arrived. The newest is last.
- `session.tokens` gives the address validation tokens the server sent in NEW_TOKEN frames, newest last. A connection that presents one need not have its address validated again.
- Pass a ticket as `session:` and a token as `token:` to `Client.connect`. Each is for one connection only: using one again links the connections for anyone watching, so drop it once used.
- With `early_data: true` and a ticket that allows 0-RTT, the block is given the session at once, and the requests it makes go in 0-RTT. While 0-RTT goes, HTTP/3 keeps to the SETTINGS stored in the ticket.

```ruby
ticket = token = nil
Raiha::Runtime::Client.connect("localhost", 4433, config: Raiha::QUIC::Config.new, tls_config: tls, keyring:) do |session|
  client = Raiha::Runtime::HTTP3::Client.new(session)
  client.get("/")
  ticket = client.tickets.last
  token = session.tokens.last
end

Raiha::Runtime::Client.connect("localhost", 4433, config: Raiha::QUIC::Config.new, tls_config: tls, keyring:, session: ticket, token:, early_data: true) do |session|
  client = Raiha::Runtime::HTTP3::Client.new(session)
  response = begin
    client.get("/")
  rescue Raiha::QUIC::Error::ZeroRttRejected
    client.get("/")
  end
end
```

0-RTT can be replayed by an attacker, so send in it only requests that are safe to repeat. Call `session.wait_handshake` before any other request to wait until the handshake has completed.

When the server rejects 0-RTT, each request that went in it raises `Raiha::QUIC::Error::ZeroRttRejected`, and HTTP/3 starts over on the connection. Whether to send the request again is up to the application; requests made after the rejection go normally. `session.connection.zero_rtt_state` tells how 0-RTT went (`:accepted` or `:rejected`), and `session.handshake.resumed` whether the connection resumed.

A connection given to the block is not tried at another address, because what it sent in 0-RTT must not be sent again without the application deciding to.

## QUIC

`Runtime::Server` and `Runtime::Client.connect` run QUIC connections without HTTP/3: the application gets a `Session` and reads and writes its streams. The HTTP/3 server and client above are built on them, so the options of this section apply to those as well.

### A minimal echo

```ruby
require "raiha/runtime"
require "async"
require "./examples/_certificate" # a throwaway CA and a certificate for "localhost"

Warning[:experimental] = false # async reads with IO::Buffer, which Ruby 4.0 calls experimental

registry = Raiha::TLS::Extension::Registry::BUILTIN.with(Raiha::QUIC::TransportParameters::Extension)
alpn = ["echo"]

server_tls = Raiha::TLS::Config.server(profile: Raiha::TLS::Profile::QUIC, alpn:, registry:)
server = Raiha::Runtime::Server.new(
  config: Raiha::QUIC::Config.new,
  tls_config: server_tls,
  keyring: Raiha::TLS::Keyring.server(config: server_tls, identities: [ExampleCertificate.identity]),
  host: "127.0.0.1", port: 0
)

client_tls = Raiha::TLS::Config.client(trust_anchors: [ExampleCertificate.ca_der], profile: Raiha::TLS::Profile::QUIC, alpn:, registry:)

Async do
  serving = Async do
    server.run do |session|
      session.each_stream do |stream|
        stream << stream.read
        stream.close_write
      end
    end
  end
  sleep 0.01 until server.local_address

  reply = Raiha::Runtime::Client.connect("127.0.0.1", server.local_address[1], server_name: "localhost",
    config: Raiha::QUIC::Config.new, tls_config: client_tls, keyring: Raiha::TLS::Keyring.client(config: client_tls)) do |session|
    stream = session.open_stream
    stream << "hello"
    stream.close_write
    stream.read
  end
  puts reply # => hello

  server.stop(timeout: 1)
  serving.wait
end
```

Run it from the root of the repository with `bundle exec ruby -Ilib echo.rb`. [examples/high_level_loopback.rb](../examples/high_level_loopback.rb) is the same echo, run as one of the examples.

### Server

```ruby
server = Raiha::Runtime::Server.new(config:, tls_config:, keyring:, host: "::", port: 443)
server.run { |session| ... }
```

| Argument | Default | Meaning |
| --- | --- | --- |
| `config` | required | The `QUIC::Config` of every connection. |
| `tls_config` | required | A server `TLS::Config` with the QUIC profile. |
| `keyring` | required | The `TLS::Keyring.server` of `tls_config`, holding the certificates. |
| `host` | `"::"` | The address to bind. On Linux, `"::"` takes IPv4 too. |
| `port` | `443` | The UDP port. `0` lets the OS choose one. |
| `max_connections` | `1024` | The most connections at a time. Clients beyond it are refused with `CONNECTION_REFUSED`. |
| `max_unvalidated` | `max_connections / 2` | How many connections may have unvalidated addresses before new clients are sent a Retry. `0` sends every new client one. |
| `qlog_dir` | `nil` | A directory for a qlog of each connection. See [qlog.md](qlog.md). |
| `anti_replay` | a new `TLS::AntiReplay::Memory` | Where the 0-RTT the server took is recorded, so that each ClientHello's 0-RTT is taken at most once. |
| `app_early_data_context` | `""` | What your 0-RTT depends on. A ticket issued under another context has its 0-RTT rejected. |
| `worker`, `stop_error_code` | `nil`, `0` | Set by `Runtime::Workers`. A `worker` given along with `host` or `port` raises `ArgumentError`. |

`run` binds the socket and serves until the server stops. It gives the block the `Session` of each connection once its handshake completes, in a fiber of its own. When the block returns, the server lets what the streams sent be acknowledged, until three PTOs go with no more of it acknowledged or 30 seconds in all, then closes the connection with application error 0. When the block raises, the connection closes with `INTERNAL_ERROR` and the exception goes on to the scheduler. Other connections are not touched either way. `run` raises whatever failed inside the runtime.

`local_address` is `[address, port]` once `run` has bound the socket, and `nil` before. With `port: 0`, wait for it as the example does.

`stop(timeout: 30, error_code: 0)` asks the server to stop. It takes no lock and does not block, so a signal handler may call it, and only the first call counts. The server takes no new connection and tells every `Session` it is `stopping?`. The sessions get `timeout` seconds to end their connections. Those left open are then closed with `error_code`, and `run` returns. A connection whose block has not started yet is closed at once.

`reconfigure(tls_config:, keyring:)` makes connections from then on use another TLS config and keyring, such as a renewed certificate. Connections already taken keep theirs, and the QUIC `Config` cannot be changed.

#### Address validation and Retry

The server counts the connections whose client address has not been validated yet. Those are the handshakes admitted and not finished, plus the connections whose handshake has not validated the address. Once there are `max_unvalidated` of them, a client that shows no token is sent a Retry first. Initials from spoofed addresses therefore cannot use up all of `max_connections`. A token from an earlier connection (`Session#tokens`, given back to `Client.connect(token:)`) skips the Retry.

#### Preferred addresses

With `QUIC::Config.new(preferred_address: {ipv4: [host, port], ipv6: [host, port]})`, the server offers its clients an address to move to once the handshake is confirmed. `run` binds a socket to each preferred address that the first socket does not already cover, and raises the bind error if one fails, so no client is offered an address nobody listens at. The client moves on its own; there is no call for it.

#### Workers

`Raiha::Runtime::Workers` runs several servers, each in a Ractor of its own, on one port. See [Several Ractors with Workers](#several-ractors-with-workers).

### Client

```ruby
value = Raiha::Runtime::Client.connect(host, port, config:, tls_config:, keyring:) { |session| ... }
```

| Argument | Default | Meaning |
| --- | --- | --- |
| `host`, `port` | required | Where to connect. The host is resolved with `Addrinfo.getaddrinfo`. |
| `config` | required | The `QUIC::Config` of the connection. |
| `tls_config`, `keyring` | required | A client `TLS::Config` with the QUIC profile, and its `TLS::Keyring.client`. |
| `server_name` | `host` | The name sent in SNI and checked against the certificate. |
| `connect_timeout` | `5.0` | Seconds each address has to complete its handshake. |
| `qlog_dir` | `nil` | A directory for a qlog of each connection tried. |
| `session`, `token`, `early_data` | `nil`, `nil`, `false` | Resumption and 0-RTT; see below. |

`connect` tries each address of the host in turn, each from a socket of its own, until one completes its handshake within `connect_timeout`. It then calls the block with the `Session` and returns the block's value. There is no HTTP/3 discovery (Alt-Svc or HTTPS records) and no fallback to TCP: the host and port are taken to speak QUIC.

When the block returns, what the streams sent is let be acknowledged, until three PTOs go with no more of it acknowledged or 30 seconds in all, so a final write is not cut short. The connection then closes with application error 0, or with the close code of the protocol attached to the session (`H3_NO_ERROR` for HTTP/3). The closing period is not waited out: the CONNECTION_CLOSE is sent and the socket closes.

When no address works, `connect` raises `Raiha::Runtime::ConnectError`. Its `errors` is a list of `[address, error]` pairs: a `QUIC::ClosedError` for a connection that closed or timed out, a `SystemCallError` for a socket that could not be made, or a `SocketError` for a name that did not resolve.

```text
could not connect to 127.0.0.1:9 (["127.0.0.1", 9]: closed with transport error 0x0: no handshake in 1 seconds)
```

Each socket is bound to `"::"`, which on Linux sends to IPv4 too, so the connection can move to a preferred address of either family. Where `"::"` takes no IPv4, as on OpenBSD, or cannot be bound at all, the client binds `"0.0.0.0"` for an IPv4 server. See [platforms.md](platforms.md).

#### Resuming a connection

A client's `Session#tickets` holds the session tickets the server sent (the newest 8). `Session#tokens` holds the NEW_TOKEN tokens (also the newest 8). Pass one ticket as `session:` and one token as `token:` to a later `connect` to resume and to skip address validation. Use each only once and then drop it, since reusing one links the two connections for anyone watching.

With `early_data: true` and a ticket that allows 0-RTT, the block is called before the handshake completes, and what it writes goes in 0-RTT. An attacker can replay 0-RTT, so write only what is safe to repeat before calling `session.wait_handshake`. A connection given to the block is not retried at another address. If the server rejects the 0-RTT, the streams opened in it raise `QUIC::Error::ZeroRttRejected`, and sending that data again is up to you. `session.connection.zero_rtt_state` is `:disabled`, `:pending`, `:accepted` or `:rejected`.

```ruby
reply = Raiha::Runtime::Client.connect("127.0.0.1", port, server_name: "localhost", config: Raiha::QUIC::Config.new,
  tls_config: client_tls, keyring: client_keyring, session: ticket, token:, early_data: true) do |session|
  stream = session.open_stream
  (stream << "safe to repeat").close_write
  session.wait_handshake
  stream.read
end
```

The server's side of this, ticket keys and 0-RTT, is set in its `TLS::Config`; see [configuration.md](configuration.md#tickets-and-0-rtt).

### Session

| Method | What it does |
| --- | --- |
| `open_stream(direction: :bidi)` | Opens a stream (`:bidi` or `:uni`), waiting until the peer's stream limit allows it. Returns a `Stream`. |
| `accept_stream` | Waits for the next stream the peer opens. Returns `nil` once the connection has closed, or once the server is stopping and no stream has come. |
| `each_stream { \|stream\| }` | Calls the block for each stream the peer opens, each in a fiber of its own, until `accept_stream` returns `nil`. |
| `wait_handshake` | Waits until the handshake has completed. |
| `wait_ready` | Waits until the application may send: once the handshake has completed, or right away while 0-RTT is pending. |
| `wait_acknowledged(seconds)` | Waits up to `seconds` until everything the streams sent has been acknowledged. Returns whether it has. |
| `close(error_code: 0, reason: "")` | Closes the connection with an application error code. |
| `close_when_acknowledged(error_code: 0, timeout: 30)` | Closes once what was sent is acknowledged, or once three PTOs go with no more of it acknowledged, or after `timeout` seconds in all. |
| `closed?` | Whether the connection has closed. |
| `stopping?`, `stop_deadline` | At a server, whether it is stopping, and the clock time at which it will close what is left. |
| `handshake` | The `TLS::Event::HandshakeComplete` of the handshake once it is done, with what was negotiated. |
| `tickets`, `tokens` | At a client, the session tickets and NEW_TOKEN tokens the server sent. |
| `server_name`, `resumed` | At a client, the server's name and the ticket given to `connect`. |
| `connection` | The underlying `QUIC::Connection`, for what the session does not wrap. |

Once the connection has closed, a call that waits raises `Raiha::QUIC::ClosedError`, whose message gives the close reason. There are two exceptions: `accept_stream` returns `nil` instead, and a read still returns the data that arrived before the close. If the runtime itself stops, a waiting call raises whatever failed in it.

#### Streams

A `Stream` is read and written like an IO.

- `read(length)` returns up to `length` bytes as soon as there are any, and `nil` at the end of the stream.
- `read` with no length returns everything up to the end, and `""` if the stream has already ended.
- `write(data)` writes all of `data`, waiting while the peer's flow control holds it back, and returns its length. `<<` does the same and returns the stream.
- `close_write` ends the sending part (FIN).
- `id` is the stream ID.

A unidirectional stream can only be written by the side that opened it and only read by the other.

When the peer resets a stream you are reading, `read` raises `Raiha::Runtime::StreamReset`. When the peer sends STOP_SENDING for a stream you are writing, `write` raises it. `error_code` and `stream_id` tell which. `Stream` has no reset of its own; reset a stream through the core connection and wake the runtime:

```ruby
session.connection.stream_reset(stream.id, error_code: 7)          # RESET_STREAM
session.connection.stream_stop_sending(stream.id, error_code: 7)   # STOP_SENDING
session.changed
```

#### Not in the runtime

The runtime's `Session` has no API for QUIC DATAGRAM frames. Even with `max_datagram_frame_size` set in the `Config`, the session drops the DATAGRAM frames it receives; drive the connection yourself, as [QUIC](quic.md) shows, to use them. Connection migration needs no API: a server follows a client that moves, and a client moves to the server's preferred address on its own.
